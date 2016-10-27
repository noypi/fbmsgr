package fbmsgr

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/rand"
	"net/url"
	"strconv"
	"time"
)

const pollErrTimeout = time.Second * 5

// An Event is a notification pushed to the client by the
// server.
type Event interface{}

// A MessageEvent is an Event containing a new message.
type MessageEvent struct {
	Body       string
	SenderFBID string

	// TODO: information here about the group chat if there
	// was one.

	// TODO: information here about attachments.
}

// Events returns a channel of events.
// This will start listening for events if no listener was
// already running.
func (s *Session) Events() <-chan Event {
	s.pollLock.Lock()
	defer s.pollLock.Unlock()
	if s.pollChan == nil {
		ch := make(chan Event, 1)
		s.pollChan = ch
		go s.poll(ch)
	}
	return s.pollChan
}

// EventsError returns the error which caused the events
// channel to be closed (if it is closed).
func (s *Session) EventsError() error {
	s.pollLock.Lock()
	defer s.pollLock.Unlock()
	return s.pollErr
}

func (s *Session) poll(ch chan<- Event) {
	host, err := s.callReconnect()
	if err != nil {
		s.pollFailed(errors.New("reconnect: "+err.Error()), ch)
		return
	}
	pool, token, err := s.fetchPollingInfo(host)
	if err != nil {
		s.pollFailed(err, ch)
		return
	}

	var msgsRecv int
	seq := 1
	for {
		values := url.Values{}
		values.Set("cap", "8")
		values.Set("cb", "anuk")
		values.Set("channel", "p_"+s.userID)
		values.Set("clientid", "3342de8f")
		values.Set("idle", "0")
		values.Set("isq", "243")
		values.Set("msgr_region", "FRC")
		values.Set("msgs_recv", strconv.Itoa(msgsRecv))
		values.Set("partition", "-2")
		values.Set("pws", "fresh")
		values.Set("qp", "y")
		values.Set("seq", strconv.Itoa(seq))
		values.Set("state", "offline")
		values.Set("uid", s.userID)
		values.Set("viewer_uid", s.userID)
		values.Set("sticky_pool", pool)
		values.Set("sticky_token", token)
		u := "https://0-edge-chat.messenger.com/pull?" + values.Encode()
		seq++
		response, err := s.jsonForGet(u)
		if err != nil {
			time.Sleep(pollErrTimeout)
			continue
		}
		msgs, err := parseMessages(response)
		if err != nil {
			time.Sleep(pollErrTimeout)
		} else {
			msgsRecv += len(msgs)
			s.dispatchMessages(ch, msgs)
		}
	}
}

func (s *Session) dispatchMessages(ch chan<- Event, msgs []map[string]interface{}) {
	for _, m := range msgs {
		t, ok := m["type"].(string)
		if !ok {
			continue
		}
		switch t {
		case "delta":
			var deltaObj struct {
				Delta struct {
					Body string `json:"body"`
					Meta struct {
						Actor string `json:"actorFbId"`
					} `json:"messageMetadata"`
				} `json:"delta"`
			}
			if putJSONIntoObject(m, &deltaObj) == nil {
				if deltaObj.Delta.Body != "" {
					ch <- MessageEvent{
						Body:       deltaObj.Delta.Body,
						SenderFBID: deltaObj.Delta.Meta.Actor,
					}
				}
			}
		}
	}
}

func (s *Session) fetchPollingInfo(host string) (stickyPool, stickyToken string, err error) {
	values := url.Values{}
	values.Set("cap", "8")
	cbStr := ""
	for i := 0; i < 4; i++ {
		cbStr += string(byte(rand.Intn(26)) + 'a')
	}
	values.Set("cb", cbStr)
	values.Set("channel", "p_"+s.userID)
	values.Set("clientid", "3342de8f")
	values.Set("idle", "0")
	values.Set("msgr_region", "FRC")
	values.Set("msgs_recv", "0")
	values.Set("partition", "-2")
	values.Set("pws", "fresh")
	values.Set("qp", "y")
	values.Set("seq", "0")
	values.Set("state", "offline")
	values.Set("uid", s.userID)
	values.Set("viewer_uid", s.userID)
	u := "https://0-" + host + ".messenger.com/pull?" + values.Encode()
	response, err := s.jsonForGet(u)
	if err != nil {
		return "", "", err
	}
	var respObj struct {
		Type   string `json:"t"`
		LbInfo *struct {
			Sticky string `json:"sticky"`
			Pool   string `json:"pool"`
		} `json:"lb_info"`
	}
	if err := json.Unmarshal(response, &respObj); err != nil {
		return "", "", errors.New("parse init JSON: " + err.Error())
	}
	if respObj.Type == "lb" && respObj.LbInfo != nil {
		return respObj.LbInfo.Pool, respObj.LbInfo.Sticky, nil
	}
	return "", "", errors.New("unexpected initial polling response")
}

func (s *Session) callReconnect() (host string, err error) {
	values, err := s.commonParams()
	if err != nil {
		return "", err
	}
	values.Set("reason", "6")
	u := "https://www.messenger.com/ajax/presence/reconnect.php?" + values.Encode()
	response, err := s.jsonForGet(u)
	if err != nil {
		return "", err
	}

	var respObj struct {
		Payload struct {
			Host string `json:"host"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(response, &respObj); err != nil {
		return "", err
	}
	return respObj.Payload.Host, nil
}

func (s *Session) pollFailed(e error, ch chan<- Event) {
	s.pollLock.Lock()
	s.pollErr = e
	close(ch)
	s.pollLock.Unlock()
}

// parseMessages extracts all of the "msg" payloads from a
// polled event body.
func parseMessages(data []byte) (list []map[string]interface{}, err error) {
	reader := json.NewDecoder(bytes.NewBuffer(data))
	for reader.More() {
		var objVal struct {
			Type     string                   `json:"t"`
			Messages []map[string]interface{} `json:"ms"`
		}
		if err := reader.Decode(&objVal); err != nil {
			return nil, err
		}
		if objVal.Type == "msg" {
			list = append(list, objVal.Messages...)
		}
	}
	return
}

// putJSONIntoObject turns source into JSON, then
// unmarshals it back into the destination.
func putJSONIntoObject(source, dest interface{}) error {
	encoded, err := json.Marshal(source)
	if err != nil {
		return err
	}
	return json.Unmarshal(encoded, &dest)
}