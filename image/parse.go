package image

import (
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
)

type Reference struct {
	Registry   string
	Namespace  string
	Repository string
	Tag        string
	Digest     string
}

func ParseReference(image string) (Reference, error) {
	r, err := name.ParseReference(image)
	if err != nil {
		return Reference{}, err
	}

	s := strings.Split(r.Context().RepositoryStr(), "/")
	ref := Reference{
		Registry:   r.Context().RegistryStr(),
		Namespace:  s[0],
		Repository: s[1],
	}

	switch v := r.(type) {
	case name.Tag:
		ref.Tag = v.TagStr()
	case name.Digest:
		ref.Digest = v.DigestStr()
	}
	return ref, nil
}
