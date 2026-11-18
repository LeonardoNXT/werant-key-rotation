package ports

type Id interface {
	IdGenerator() (*string, error)
}
