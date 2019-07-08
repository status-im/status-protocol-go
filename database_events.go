package statusproto

import (
	"github.com/ethereum/go-ethereum/event"

	protocol "github.com/status-im/status-protocol-go/v1"
)

type databaseWithEvents struct {
	database
	feed *event.Feed
}

func newDatabaseWithEvents(db database, feed *event.Feed) databaseWithEvents {
	return databaseWithEvents{database: db, feed: feed}
}

func (db databaseWithEvents) SaveMessages(c Contact, msgs []*protocol.Message) (int64, error) {
	rowid, err := db.database.SaveMessages(c, msgs)
	if err != nil {
		return rowid, err
	}
	for _, m := range msgs {
		ev := messageEvent{
			baseEvent: baseEvent{
				Contact: c,
				Type:    EventTypeMessage,
			},
			Message: m,
		}
		db.feed.Send(Event{ev})
	}
	return rowid, err
}
