package calendar

import (
	"errors"
	"testing"
)

func TestUnavailableCalendarFailsClosed(t *testing.T) {
	calendar := NewGoogleCalendar(&GoogleCalendarConfig{})
	if err := calendar.Configure("user@example.com"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Configure error = %v", err)
	}
	isRemote, status, body := RemoteError(ErrUnavailable)
	if !isRemote || status != 501 || body == "" {
		t.Fatalf("RemoteError = %v, %d, %q", isRemote, status, body)
	}
}
