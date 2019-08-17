package statusproto

import (
	"bytes"
	"database/sql"
	"io/ioutil"
	"math"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/status-im/status-protocol-go/sqlite"
	"github.com/stretchr/testify/require"
)

func TestTableUserMessagesAllFieldsCount(t *testing.T) {
	db := sqlitePersistence{}
	expected := len(strings.Split(db.tableUserMessagesLegacyAllFields(), ","))
	require.Equal(t, expected, db.tableUserMessagesLegacyAllFieldsCount())
}

func TestSaveMessages(t *testing.T) {
	db, err := openTestDB()
	require.NoError(t, err)
	p := sqlitePersistence{db: db}

	for i := 0; i < 10; i++ {
		id := strconv.Itoa(i)
		err := insertMinimalMessage(p, id)
		require.NoError(t, err)

		m, err := p.MessageByID(id)
		require.NoError(t, err)
		require.EqualValues(t, id, m.ID)
	}
}

func TestMessageByID(t *testing.T) {
	db, err := openTestDB()
	require.NoError(t, err)
	p := sqlitePersistence{db: db}
	id := "1"

	err = insertMinimalMessage(p, id)
	require.NoError(t, err)

	m, err := p.MessageByID(id)
	require.NoError(t, err)
	require.EqualValues(t, id, m.ID)
}

func TestMessageExists(t *testing.T) {
	db, err := openTestDB()
	require.NoError(t, err)
	p := sqlitePersistence{db: db}
	id := "1"

	err = insertMinimalMessage(p, id)
	require.NoError(t, err)

	exists, err := p.MessageExists(id)
	require.NoError(t, err)
	require.True(t, exists)
}

func TestMessageByChatID(t *testing.T) {
	db, err := openTestDB()
	require.NoError(t, err)
	p := sqlitePersistence{db: db}
	chatID := "super-chat"
	count := 1000
	pageSize := 50

	for i := 0; i < count; i++ {
		err := p.SaveMessage(&MessageLegacy{
			ID:             strconv.Itoa(i),
			ChatID:         chatID,
			RawPayloadHash: strconv.Itoa(i),
			From:           []byte("me"),
			ClockValue:     int64(i),
		})
		require.NoError(t, err)

		// Add some other chats.
		if count%5 == 0 {
			err := p.SaveMessage(&MessageLegacy{
				ID:             strconv.Itoa(count + i),
				ChatID:         "other-chat",
				RawPayloadHash: strconv.Itoa(count + i),
				From:           []byte("me"),
				ClockValue:     int64(i),
			})
			require.NoError(t, err)
		}
	}

	// Add some out-of-order message. Add more than page size.
	outOfOrderCount := pageSize + 1
	allCount := count + outOfOrderCount
	for i := 0; i < pageSize+1; i++ {
		err := p.SaveMessage(&MessageLegacy{
			ID:             strconv.Itoa(count*2 + i),
			ChatID:         chatID,
			RawPayloadHash: strconv.Itoa(count*2 + i),
			From:           []byte("me"),
			ClockValue:     int64(i), // use very old clock values
		})
		require.NoError(t, err)
	}

	var (
		result []*MessageLegacy
		cursor string
		iter   int
	)
	for {
		var (
			items []*MessageLegacy
			err   error
		)

		items, cursor, err = p.MessageByChatID(chatID, cursor, pageSize)
		require.NoError(t, err)
		result = append(result, items...)

		iter++
		if len(cursor) == 0 || iter > count {
			break
		}
	}
	require.Equal(t, "", cursor) // for loop should exit because of cursor being empty
	require.EqualValues(t, math.Ceil(float64(allCount)/float64(pageSize)), iter)
	require.Equal(t, len(result), allCount)
	require.True(
		t,
		// Verify descending order.
		sort.SliceIsSorted(result, func(i, j int) bool {
			return result[i].ClockValue > result[j].ClockValue
		}),
	)
}

func TestMessageByChatIDWithTheSameClockValues(t *testing.T) {
	db, err := openTestDB()
	require.NoError(t, err)
	p := sqlitePersistence{db: db}
	chatID := "super-chat"
	clockValues := []int64{10, 10, 9, 9, 9, 11, 12, 11, 100000, 6, 4, 5, 5, 5, 5}
	count := len(clockValues)
	pageSize := 2

	for i, clock := range clockValues {
		err := p.SaveMessage(&MessageLegacy{
			ID:             strconv.Itoa(i),
			ChatID:         chatID,
			RawPayloadHash: strconv.Itoa(i),
			From:           []byte("me"),
			ClockValue:     clock,
		})
		require.NoError(t, err)
	}

	var (
		result []*MessageLegacy
		cursor string
		iter   int
	)
	for {
		var (
			items []*MessageLegacy
			err   error
		)

		items, cursor, err = p.MessageByChatID(chatID, cursor, pageSize)
		require.NoError(t, err)
		result = append(result, items...)

		iter++
		if cursor == "" || iter > count {
			break
		}
	}
	require.Empty(t, cursor) // for loop should exit because of cursor being empty
	require.Len(t, result, count)
	// Verify the order.
	expectedClockValues := make([]int64, len(clockValues))
	copy(expectedClockValues, clockValues)
	sort.Slice(expectedClockValues, func(i, j int) bool {
		return expectedClockValues[i] > expectedClockValues[j]
	})
	resultClockValues := make([]int64, 0, len(clockValues))
	for _, m := range result {
		resultClockValues = append(resultClockValues, m.ClockValue)
	}
	require.EqualValues(t, expectedClockValues, resultClockValues)
}

func TestUnseenMessageIDs(t *testing.T) {
	db, err := openTestDB()
	require.NoError(t, err)
	p := sqlitePersistence{db: db}
	count := 10

	for i := 0; i < count; i++ {
		id := strconv.Itoa(i)
		err := insertMinimalMessage(p, id)
		require.NoError(t, err)
	}

	ids, err := p.UnseenMessageIDs()
	require.NoError(t, err)
	require.Len(t, ids, count)
}

func TestMessagesFrom(t *testing.T) {
	db, err := openTestDB()
	require.NoError(t, err)
	p := sqlitePersistence{db: db}
	count := 10

	for i := 0; i < count; i++ {
		id := strconv.Itoa(i)
		err := insertMinimalMessage(p, id)
		require.NoError(t, err)

		err = p.SaveMessage(&MessageLegacy{
			ID:             id,
			RawPayloadHash: id,
			From:           []byte("other"),
		})
		require.NoError(t, err)
	}

	messages, err := p.MessagesFrom([]byte("other"))
	require.NoError(t, err)
	require.Len(t, messages, 10)
	require.Condition(t, func() bool {
		for _, m := range messages {
			if !bytes.Equal(m.From, []byte("other")) {
				return false
			}
		}
		return true
	})
}

func TestDeleteMessageByID(t *testing.T) {
	db, err := openTestDB()
	require.NoError(t, err)
	p := sqlitePersistence{db: db}
	id := "1"

	err = insertMinimalMessage(p, id)
	require.NoError(t, err)

	m, err := p.MessageByID(id)
	require.NoError(t, err)
	require.Equal(t, id, m.ID)

	err = p.DeleteMessage(m.ID)
	require.NoError(t, err)

	_, err = p.MessageByID(id)
	require.EqualError(t, err, "record not found")
}

func TestMarkMessageSeen(t *testing.T) {
	db, err := openTestDB()
	require.NoError(t, err)
	p := sqlitePersistence{db: db}
	id := "1"

	err = insertMinimalMessage(p, id)
	require.NoError(t, err)

	m, err := p.MessageByID(id)
	require.NoError(t, err)
	require.False(t, m.Seen)

	err = p.MarkMessagesSeen(m.ID)
	require.NoError(t, err)

	m, err = p.MessageByID(id)
	require.NoError(t, err)
	require.True(t, m.Seen)
}

func TestUpdateMessageOutgoingStatus(t *testing.T) {
	db, err := openTestDB()
	require.NoError(t, err)
	p := sqlitePersistence{db: db}
	id := "1"

	err = insertMinimalMessage(p, id)
	require.NoError(t, err)

	err = p.UpdateMessageOutgoingStatus(id, "new-status")
	require.NoError(t, err)

	m, err := p.MessageByID(id)
	require.NoError(t, err)
	require.Equal(t, "new-status", m.OutgoingStatus)
}

func openTestDB() (*sql.DB, error) {
	dbPath, err := ioutil.TempFile("", "")
	if err != nil {
		return nil, err
	}
	names, getter, err := prepareMigrations(defaultMigrations)
	if err != nil {
		return nil, err
	}
	return sqlite.Open(dbPath.Name(), "", sqlite.MigrationConfig{
		AssetNames:  names,
		AssetGetter: getter,
	})
}

func insertMinimalMessage(p sqlitePersistence, id string) error {
	return p.SaveMessage(&MessageLegacy{
		ID:             id,
		RawPayloadHash: id,
		From:           []byte("me"),
	})
}
