// Code generated by "stringer -type=ContactType"; DO NOT EDIT.

package statusproto

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[ContactPublicRoom-1]
	_ = x[ContactPrivate-2]
}

const _ContactType_name = "ContactPublicRoomContactPrivate"

var _ContactType_index = [...]uint8{0, 17, 31}

func (i ContactType) String() string {
	i -= 1
	if i < 0 || i >= ContactType(len(_ContactType_index)-1) {
		return "ContactType(" + strconv.FormatInt(int64(i+1), 10) + ")"
	}
	return _ContactType_name[_ContactType_index[i]:_ContactType_index[i+1]]
}
