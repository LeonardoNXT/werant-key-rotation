package adapters

import "time"

type Clock struct{}

func (Clock) NowISO8601() string {
	return time.Now().UTC().Format(time.RFC3339)
}
