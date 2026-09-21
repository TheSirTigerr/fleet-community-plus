// Package calendar defines a fail-closed calendar provider boundary.
package calendar

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/fleetdm/fleet/v4/server/fleet"
	googlecalendar "google.golang.org/api/calendar/v3"
)

var ErrUnavailable = errors.New("Community+ Google Calendar provider is unavailable")

const MockEmail = "calendar-mock@example.com"

func ClearMockEvents() {}

func ClearMockChannels() {}

func SetMockEventsToNow() {}

// ListGoogleMockEvents preserves the public test-helper shape. The production
// adapter remains fail-closed, so it never creates entries in this map.
func ListGoogleMockEvents() map[string]*googlecalendar.Event {
	return map[string]*googlecalendar.Event{}
}

func MockChannelsCount() int { return 0 }

type GoogleCalendarConfig struct {
	Context           context.Context
	IntegrationConfig *fleet.GoogleCalendarIntegration
	ServerURL         string
	Logger            *slog.Logger
}

type unavailableCalendar struct{}

func NewGoogleCalendar(_ *GoogleCalendarConfig) fleet.UserCalendar { return unavailableCalendar{} }

func RemoteError(err error) (bool, int, string) {
	if errors.Is(err, ErrUnavailable) {
		return true, 501, err.Error()
	}
	return false, 0, ""
}

func (unavailableCalendar) Configure(string) error { return ErrUnavailable }

func (unavailableCalendar) CreateEvent(time.Time, fleet.CalendarGenBodyFn, fleet.CalendarCreateEventOpts) (*fleet.CalendarEvent, error) {
	return nil, ErrUnavailable
}

func (unavailableCalendar) GetAndUpdateEvent(*fleet.CalendarEvent, fleet.CalendarGenBodyFn, fleet.CalendarGetAndUpdateEventOpts) (*fleet.CalendarEvent, bool, error) {
	return nil, false, ErrUnavailable
}

func (unavailableCalendar) UpdateEventBody(*fleet.CalendarEvent, fleet.CalendarGenBodyFn) (string, error) {
	return "", ErrUnavailable
}

func (unavailableCalendar) DeleteEvent(*fleet.CalendarEvent) error { return ErrUnavailable }

func (unavailableCalendar) StopEventChannel(*fleet.CalendarEvent) error { return ErrUnavailable }

func (unavailableCalendar) Get(*fleet.CalendarEvent, string) (interface{}, error) {
	return nil, ErrUnavailable
}
