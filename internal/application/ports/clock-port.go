package ports

type Clock interface {
	NowISO8601() string
}
