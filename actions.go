package fbmsgr

import (
	"fmt"
	"time"
)

const (
	MessageActionType = "ma-type:user-generated-message"
)

// An Action is something which occurred in a thread.
// For example, an incoming message is an action.
type Action interface {
	// ActionType returns Messenger's internal type string
	// for the action.
	// For exampe, this might be MessageActionType.
	ActionType() string

	// ActionTime returns the timestamp of the action.
	ActionTime() time.Time

	// MessageID returns the message ID of the action.
	MessageID() string

	// AuthorFBID returns the FBID of the action's sender.
	AuthorFBID() string

	// RawFields returns the raw JSON object for the action.
	RawFields() map[string]interface{}
}

// decodeAction creates the most appropriate Action type
// for the given action.
func decodeAction(m map[string]interface{}) Action {
	ga := GenericAction{RawData: m}
	switch ga.ActionType() {
	case MessageActionType:
		body, _ := m["body"].(string)
		rawAttach, _ := m["attachments"].([]interface{})
		var attachments []Attachment
		for _, x := range rawAttach {
			if x, ok := x.(map[string]interface{}); ok {
				attachments = append(attachments, decodeAttachment(x))
			}
		}
		return &MessageAction{
			GenericAction: ga,
			Body:          body,
			Attachments:   attachments,
		}
	default:
		return &ga
	}
}

// A GenericAction is an Action with no action-specific
// fields.
// It is used as a base class for other Actions, and when
// an unknown or unsupported action is encountered.
type GenericAction struct {
	// RawData contains the raw JSON value of this
	// action.
	RawData map[string]interface{}
}

// ActionType extracts the action's type.
func (g *GenericAction) ActionType() string {
	t, _ := g.RawData["action_type"].(string)
	return t
}

// ActionTime extracts the action's timestamp.
func (g *GenericAction) ActionTime() time.Time {
	if ts, ok := g.RawData["timestamp"].(float64); ok {
		return time.Unix(int64(ts/1000), (int64(ts)%1000)*1000000)
	}
	return time.Time{}
}

// MessageID extracts the action's message ID.
func (g *GenericAction) MessageID() string {
	mid, _ := g.RawData["message_id"].(string)
	return mid
}

// AuthorFBID extracts the action's sender's FBID.
func (g *GenericAction) AuthorFBID() string {
	fbid, _ := g.RawData["author"].(string)
	return stripFBIDPrefix(fbid)
}

// RawFields returns the raw data.
func (g *GenericAction) RawFields() map[string]interface{} {
	return g.RawData
}

// String returns a generic string representation of the
// action.
func (g *GenericAction) String() string {
	return fmt.Sprintf("Action<type=%s time=%s>", g.ActionType(),
		g.ActionTime().String())
}

// A MessageAction is an Action for a user-sent message.
type MessageAction struct {
	GenericAction

	Body        string
	Attachments []Attachment
}
