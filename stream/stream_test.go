package stream_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/ovh/configstore"
	"github.com/ovh/symmecrypt/keyloader"
	"github.com/ovh/symmecrypt/stream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ProviderTest() (configstore.ItemList, error) {
	ret := configstore.ItemList{
		Items: []configstore.Item{
			configstore.NewItem(
				keyloader.EncryptionKeyConfigName,
				`{"key":"5fdb8af280b007a46553dfddb3f42bc10619dcabca8d4fdf5239b09445ab1a41","identifier":"test","sealed":false,"timestamp":1522325806,"cipher":"aes-gcm"}`,
				1,
			),
			configstore.NewItem(
				keyloader.EncryptionKeyConfigName,
				`{"key":"7db2b4b695e11563edca94b0f9c7ad16919fc11eac414c1b1706cbaa3c3e61a4b884301ae4e8fbedcc4f000b9c52904f13ea9456379d373524dea7fef79b39f7","identifier":"test-composite","sealed":false,"timestamp":1522325758,"cipher":"aes-pmac-siv"}`,
				1,
			),
			configstore.NewItem(
				keyloader.EncryptionKeyConfigName,
				`{"key":"QXdDW4N/jmJzpMu7i1zu4YF1opTn7H+eOk9CLFGBSFg=","identifier":"test-composite","sealed":false,"timestamp":1522325802,"cipher":"xchacha20-poly1305"}`,
				1,
			),
		},
	}
	return ret, nil
}

func TestMain(m *testing.M) {
	configstore.RegisterProvider("test", ProviderTest)
	os.Exit(m.Run())
}

func TestIncompleteRead(t *testing.T) {
	clearContent := make([]byte, 32*1024+10)
	rand.Read(clearContent)

	k, err := keyloader.LoadKey("test")
	require.NoError(t, err)

	var bufWriter bytes.Buffer
	streamWriter := stream.NewWriter(&bufWriter, k, 32*1024)
	nbBytesWritten, err := io.Copy(streamWriter, bytes.NewReader(clearContent))
	require.NoError(t, err)
	t.Logf("%d bytes copied to streamWriter", nbBytesWritten)
	require.NoError(t, streamWriter.Close())

	streamReader := stream.NewReader(strings.NewReader(bufWriter.String()), k, 32*1024)
	var firstPart = make([]byte, 32*1024)
	nbBytesReaden1, err := streamReader.Read(firstPart)
	t.Logf("%d bytes read the first time", nbBytesReaden1)
	require.NoError(t, err)

	var secondPart = make([]byte, 32*1024)
	nbBytesReaden2, err := streamReader.Read(secondPart)
	t.Logf("%d bytes read the second time", nbBytesReaden2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "EOF")

	require.Equal(t, 32*1024+10, nbBytesReaden1+nbBytesReaden2)

}
