// Package est provides Community+'s optional EST service construction boundary.
package est

import "log/slog"

type Service struct{}

type Option func(*Service)

func WithLogger(_ *slog.Logger) Option { return func(*Service) {} }

func NewService(opts ...Option) *Service {
	svc := &Service{}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}
