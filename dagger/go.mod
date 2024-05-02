module dagger/reverst

go 1.21.7

require (
	github.com/99designs/gqlgen v0.17.31
	github.com/Khan/genqlient v0.6.0
	github.com/vektah/gqlparser/v2 v2.5.6
	golang.org/x/exp v0.0.0-20240416160154-fe59bbe5cc7f
	golang.org/x/sync v0.7.0
)

require github.com/stretchr/testify v1.9.0 // indirect

replace go.flipt.io/reverst => ../
