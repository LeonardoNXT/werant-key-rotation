package ports

type Query interface {
	IsFirstRotation() (bool, error)
}
