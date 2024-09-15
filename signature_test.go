package httpsigver

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const happyPathPostHandlerContent = `{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/security/v1",
    {
      "manuallyApprovesFollowers": "as:manuallyApprovesFollowers",
      "toot": "http://joinmastodon.org/ns#",
      "featured": {
        "@id": "toot:featured",
        "@type": "@id"
      },
      "featuredTags": {
        "@id": "toot:featuredTags",
        "@type": "@id"
      },
      "alsoKnownAs": {
        "@id": "as:alsoKnownAs",
        "@type": "@id"
      },
      "movedTo": {
        "@id": "as:movedTo",
        "@type": "@id"
      },
      "schema": "http://schema.org#",
      "PropertyValue": "schema:PropertyValue",
      "value": "schema:value",
      "discoverable": "toot:discoverable",
      "Device": "toot:Device",
      "Ed25519Signature": "toot:Ed25519Signature",
      "Ed25519Key": "toot:Ed25519Key",
      "Curve25519Key": "toot:Curve25519Key",
      "EncryptedMessage": "toot:EncryptedMessage",
      "publicKeyBase64": "toot:publicKeyBase64",
      "deviceId": "toot:deviceId",
      "claim": {
        "@type": "@id",
        "@id": "toot:claim"
      },
      "fingerprintKey": {
        "@type": "@id",
        "@id": "toot:fingerprintKey"
      },
      "identityKey": {
        "@type": "@id",
        "@id": "toot:identityKey"
      },
      "devices": {
        "@type": "@id",
        "@id": "toot:devices"
      },
      "messageFranking": "toot:messageFranking",
      "messageType": "toot:messageType",
      "cipherText": "toot:cipherText",
      "suspended": "toot:suspended",
      "memorial": "toot:memorial",
      "indexable": "toot:indexable",
      "Hashtag": "as:Hashtag",
      "focalPoint": {
        "@container": "@list",
        "@id": "toot:focalPoint"
      }
    }
  ],
  "id": "https://social.matej-lach.me/user/MatejLach",
  "type": "Person",
  "following": "https://social.matej-lach.me/user/MatejLach/following",
  "followers": "https://social.matej-lach.me/user/MatejLach/followers",
  "inbox": "https://social.matej-lach.me/user/MatejLach/inbox",
  "outbox": "https://social.matej-lach.me/user/MatejLach/outbox",
  "featured": "https://social.matej-lach.me/user/MatejLach/collections/featured",
  "featuredTags": "https://social.matej-lach.me/user/MatejLach/collections/tags",
  "preferredUsername": "MatejLach",
  "name": "Matej Ľach  ✅",
  "summary": "<p>Free software enthusiast, <a href=\"https://social.matej-lach.me/tags/golang\" class=\"mention hashtag\" rel=\"tag\">#<span>golang</span></a>, <a href=\"https://social.matej-lach.me/tags/rustlang\" class=\"mention hashtag\" rel=\"tag\">#<span>rustlang</span></a>, <a href=\"https://social.matej-lach.me/tags/swiftlang\" class=\"mention hashtag\" rel=\"tag\">#<span>swiftlang</span></a>  . Working on a question/answer <a href=\"https://social.matej-lach.me/tags/ActivityPub\" class=\"mention hashtag\" rel=\"tag\">#<span>ActivityPub</span></a> server. <a href=\"https://social.matej-lach.me/tags/systemd\" class=\"mention hashtag\" rel=\"tag\">#<span>systemd</span></a> aficionado :-)</p>",
  "url": "https://social.matej-lach.me/@MatejLach",
  "manuallyApprovesFollowers": false,
  "discoverable": true,
  "indexable": false,
  "published": "2017-10-26T00:00:00Z",
  "memorial": false,
  "devices": "https://social.matej-lach.me/user/MatejLach/collections/devices",
  "publicKey": {
    "id": "https://social.matej-lach.me/user/MatejLach#main-key",
    "owner": "https://social.matej-lach.me/user/MatejLach",
    "publicKeyPem": "\n-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuZ0Mzoe/DkgiTpkbyZUU LNfOmi5qaOpwlMX6AfHDohJtcKukrTXcEABpRQOitJ7sjHuYDp3T9Oo2BKK7u3yS tG+JfVCF7zySPbySI4JnevoWdRw47O2A7eqAaGaZ1tE3G9aaW6C4IN24hVF2Jw4j pxPpQJjko3cDyLD1+41dDCLX66bg9Bp77wz/rVWmuB0Sh0iiLgknT/hFBUvw5K1C ml6IpDFS1zpGzKrKBOOrFhwsxrcfhSR09UVTaVqYIaQyLSe/4rE/RygexvOvHgNX ccFRwe029ay7aq4PWsS2cC2cZLYSGoUdR0IjqcobwcgmLnatdOUdewGK0KpQ4QO9 RwIDAQAB\n-----END PUBLIC KEY-----\n"
  },
  "tag": [
    {
      "type": "Hashtag",
      "href": "https://social.matej-lach.me/tags/golang",
      "name": "#golang"
    },
    {
      "type": "Hashtag",
      "href": "https://social.matej-lach.me/tags/activitypub",
      "name": "#activitypub"
    },
    {
      "type": "Hashtag",
      "href": "https://social.matej-lach.me/tags/rustlang",
      "name": "#rustlang"
    },
    {
      "type": "Hashtag",
      "href": "https://social.matej-lach.me/tags/swiftlang",
      "name": "#swiftlang"
    },
    {
      "type": "Hashtag",
      "href": "https://social.matej-lach.me/tags/systemd",
      "name": "#systemd"
    }
  ],
  "attachment": [],
  "endpoints": {
    "sharedInbox": "https://social.matej-lach.me/inbox"
  },
  "icon": {
    "type": "Image",
    "mediaType": "image/png",
    "url": "https://social.matej-lach.me/system/accounts/avatars/000/000/001/original/6e9242b03795bf80.png"
  },
  "image": {
    "type": "Image",
    "mediaType": "image/png",
    "url": "https://social.matej-lach.me/system/accounts/headers/000/000/001/original/f18240c45b0ac254.png"
  }
}`

const happyPathGetHandlerContent = `{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/security/v1",
    {
      "manuallyApprovesFollowers": "as:manuallyApprovesFollowers",
      "toot": "http://joinmastodon.org/ns#",
      "featured": {
        "@id": "toot:featured",
        "@type": "@id"
      },
      "featuredTags": {
        "@id": "toot:featuredTags",
        "@type": "@id"
      },
      "alsoKnownAs": {
        "@id": "as:alsoKnownAs",
        "@type": "@id"
      },
      "movedTo": {
        "@id": "as:movedTo",
        "@type": "@id"
      },
      "schema": "http://schema.org#",
      "PropertyValue": "schema:PropertyValue",
      "value": "schema:value",
      "discoverable": "toot:discoverable",
      "Device": "toot:Device",
      "Ed25519Signature": "toot:Ed25519Signature",
      "Ed25519Key": "toot:Ed25519Key",
      "Curve25519Key": "toot:Curve25519Key",
      "EncryptedMessage": "toot:EncryptedMessage",
      "publicKeyBase64": "toot:publicKeyBase64",
      "deviceId": "toot:deviceId",
      "claim": {
        "@type": "@id",
        "@id": "toot:claim"
      },
      "fingerprintKey": {
        "@type": "@id",
        "@id": "toot:fingerprintKey"
      },
      "identityKey": {
        "@type": "@id",
        "@id": "toot:identityKey"
      },
      "devices": {
        "@type": "@id",
        "@id": "toot:devices"
      },
      "messageFranking": "toot:messageFranking",
      "messageType": "toot:messageType",
      "cipherText": "toot:cipherText",
      "suspended": "toot:suspended",
      "memorial": "toot:memorial",
      "indexable": "toot:indexable",
      "Hashtag": "as:Hashtag",
      "focalPoint": {
        "@container": "@list",
        "@id": "toot:focalPoint"
      }
    }
  ],
  "id": "https://social.matej-lach.me/user/MatejLach",
  "type": "Person",
  "following": "https://social.matej-lach.me/user/MatejLach/following",
  "followers": "https://social.matej-lach.me/user/MatejLach/followers",
  "inbox": "https://social.matej-lach.me/user/MatejLach/inbox",
  "outbox": "https://social.matej-lach.me/user/MatejLach/outbox",
  "featured": "https://social.matej-lach.me/user/MatejLach/collections/featured",
  "featuredTags": "https://social.matej-lach.me/user/MatejLach/collections/tags",
  "preferredUsername": "MatejLach",
  "name": "Matej Ľach  ✅",
  "summary": "<p>Free software enthusiast, <a href=\"https://social.matej-lach.me/tags/golang\" class=\"mention hashtag\" rel=\"tag\">#<span>golang</span></a>, <a href=\"https://social.matej-lach.me/tags/rustlang\" class=\"mention hashtag\" rel=\"tag\">#<span>rustlang</span></a>, <a href=\"https://social.matej-lach.me/tags/swiftlang\" class=\"mention hashtag\" rel=\"tag\">#<span>swiftlang</span></a>  . Working on a question/answer <a href=\"https://social.matej-lach.me/tags/ActivityPub\" class=\"mention hashtag\" rel=\"tag\">#<span>ActivityPub</span></a> server. <a href=\"https://social.matej-lach.me/tags/systemd\" class=\"mention hashtag\" rel=\"tag\">#<span>systemd</span></a> aficionado :-)</p>",
  "url": "https://social.matej-lach.me/@MatejLach",
  "manuallyApprovesFollowers": false,
  "discoverable": true,
  "indexable": false,
  "published": "2017-10-26T00:00:00Z",
  "memorial": false,
  "devices": "https://social.matej-lach.me/user/MatejLach/collections/devices",
  "publicKey": {
    "id": "https://social.matej-lach.me/user/MatejLach#main-key",
    "owner": "https://social.matej-lach.me/user/MatejLach",
    "publicKeyPem": "%s"
  },
  "tag": [
    {
      "type": "Hashtag",
      "href": "https://social.matej-lach.me/tags/golang",
      "name": "#golang"
    },
    {
      "type": "Hashtag",
      "href": "https://social.matej-lach.me/tags/activitypub",
      "name": "#activitypub"
    },
    {
      "type": "Hashtag",
      "href": "https://social.matej-lach.me/tags/rustlang",
      "name": "#rustlang"
    },
    {
      "type": "Hashtag",
      "href": "https://social.matej-lach.me/tags/swiftlang",
      "name": "#swiftlang"
    },
    {
      "type": "Hashtag",
      "href": "https://social.matej-lach.me/tags/systemd",
      "name": "#systemd"
    }
  ],
  "attachment": [],
  "endpoints": {
    "sharedInbox": "https://social.matej-lach.me/inbox"
  },
  "icon": {
    "type": "Image",
    "mediaType": "image/png",
    "url": "https://social.matej-lach.me/system/accounts/avatars/000/000/001/original/6e9242b03795bf80.png"
  },
  "image": {
    "type": "Image",
    "mediaType": "image/png",
    "url": "https://social.matej-lach.me/system/accounts/headers/000/000/001/original/f18240c45b0ac254.png"
  }
}`

func TestReqSignature_verify_post_happy_path(t *testing.T) {
	postActorHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "ld+json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, happyPathPostHandlerContent)
	}

	server := httptest.NewServer(http.HandlerFunc(postActorHandler))

	defer server.Close()

	req, err := http.NewRequest(http.MethodPost, server.URL, strings.NewReader("some toot"))
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256([]byte("some toot"))
	digestB64 := base64.StdEncoding.EncodeToString(digest[:])

	req.Header.Set("(request-target)", "post /inbox")
	req.Header.Set("host", "localhost")
	req.Header.Set("date", "2023-01-03 3:47PM") // the date is not parsed and format is not verified in non-strict mode so it can be arbitrary
	req.Header.Set("content-type", "ld+json")
	req.Header.Set("Signature", fmt.Sprintf("keyId=\"%s/me#keyid\", algorithm=\"rsa-sha256\", headers=\"(request-target) host date\", signature=\"YbXJrNGJZjaR2KWK0EBIODAYALRw2MuzriebSBxXbx6FgRtGJec4Qov7dYn8yfHcuoiikt0vw3ZGEDsucfBVJjOStjJxfsK0sPM/B36jW0TugkvRE94o2MiJAmgyeUQDODvGjoo1GfTmbYyNffDyTlkbnPaB5UFuPTf+gHuYNuCge1kcN7EIeacZMtEaZv1CiBVpB9+3o+KnJY7/3XY2EBYJTTHrsImxkID/VJk6d6rIEpHY6iYNWZgkLFjIT3jSfXI8v/4X9+H4YZKenMMHl34UwxAlJQjybhZfRtMWY5rvDHIKgoOC6hsPQxP6QCwjBsp/dext/BpYGcZBBo7V5Q==\"", server.URL))
	req.Header.Set("digest", fmt.Sprintf("sha-256=%s", digestB64))

	validSignature, err := ReqHasValidSignature(context.Background(), req, "", false)
	if err != nil {
		t.Fatal(err)
	}

	assert.Truef(t, validSignature, "the request should have a valid signature")
}

func TestReqSignature_sign_verify_get_happy_path(t *testing.T) {
	privateKeyPem := new(bytes.Buffer)
	publicKeyPem := new(bytes.Buffer)
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	marshaledPubKey, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	err = pem.Encode(publicKeyPem, &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: marshaledPubKey,
	})

	marshaledPrivKey := x509.MarshalPKCS1PrivateKey(privKey)
	err = pem.Encode(privateKeyPem, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: marshaledPrivKey,
	})
	if err != nil {
		t.Fatal(err)
	}

	// convert the public key into a single line for JSON interpolation
	publicKeyPemLine := strings.ReplaceAll(publicKeyPem.String(), "\n", "\\n")

	getActorHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "ld+json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, fmt.Sprintf(happyPathGetHandlerContent, publicKeyPemLine))
	}

	server := httptest.NewServer(http.HandlerFunc(getActorHandler))

	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/user/me", server.URL), nil)
	if err != nil {
		t.Fatal(err)
	}

	reqActorPubKeyId, err := url.Parse(fmt.Sprintf("%s/user/me", server.URL))
	if err != nil {
		t.Fatal(err)
	}

	err = SignRequest(context.Background(), req, reqActorPubKeyId, privateKeyPem.String())
	if err != nil {
		t.Fatal(err)
	}

	validSignature, err := ReqHasValidSignature(context.Background(), req, "", true)
	if err != nil {
		t.Fatal(err)
	}

	assert.Truef(t, validSignature, "the request should have a valid signature")
}
