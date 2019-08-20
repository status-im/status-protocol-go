package nimstatus

import (
	"crypto/ecdsa"
	"fmt"
	"time"

	"github.com/status-im/status-protocol-go/types"

	whisper "github.com/status-im/whisper/whisperv6"
)

// #cgo LDFLAGS: /usr/local/lib/libnimbus_api.so -lm
// #include "libnim.h"
import "C"

func poll() {

	for {
		fmt.Println("POLLING")
		time.Sleep(1 * time.Microsecond)
		C.nimbus_poll()
	}
}

func Start() {
	C.NimMain()
	fmt.Println("[nim-status] Start 1")
	fmt.Println(C.nimbus_start(30306))
	//C.nimbus_subscribe(C.CString("status-test-c"), nil)
	fmt.Println("[nim-status] Start 2")

	peer1 := "enode://2d3e27d7846564f9b964308038dfadd4076e4373ac938e020708ad8819fd4fd90e5eb8314140768f782db704cb313b60707b968f8b61108a6fecd705b041746d@192.168.0.33:30303"
	peer2 := "enode://4ea35352702027984a13274f241a56a47854a7fd4b3ba674a596cff917d3c825506431cf149f9f2312a293bb7c2b1cca55db742027090916d01529fe0729643b@206.189.243.178:443"

	peer3 := "enode://94d2403d0c55b5c1627eb032c4c6ea8d30b523ae84661aafa18c539ce3af3f114a5bfe1a3cde7776988a6ab2906169dca8ce6a79e32d30c445629b24e6f59e0a@0.0.0.0:30303"
	fmt.Println(C.nimbus_add_peer(C.CString(peer1)))
	fmt.Println(C.nimbus_add_peer(C.CString(peer2)))

	fmt.Println(C.nimbus_add_peer(C.CString(peer3)))

}

func ListenAndPost() {
	fmt.Println("[nim-status] ListenAndPost 1")
	i := 0
	for {
		//fmt.Println("[nim-status] ListenAndPost (post @i==1000) i= ", i)
		C.nimbus_poll()
		t := time.Now().UnixNano() / int64(time.Millisecond)
		i = i + 1
		time.Sleep(1 * time.Microsecond)
		message := fmt.Sprintf("[\"~#c4\",[\"Message:%d\",\"text/plain\",\"~:public-group-user-message\",%d,%d,[\"^ \",\"~:chat-id\",\"status-test-c\",\"~:text\",\"Message:%d\"]]]", i, t*100, t, i)
		if i%1000 == 0 {
			fmt.Println("[nim-status] posting", message)
			C.nimbus_post(C.CString(message))
		}
	}
}

func Post(targetHost []byte, topic whisper.TopicType, keySym []byte, dst *ecdsa.PublicKey, src *ecdsa.PrivateKey, payload, padding []byte, pow float64, ttl uint32) string {
	C.nimbus_post(C.CString(string(payload)))
	return ""
}

type NimbusWhisperService struct {
	messageStoreFabric func() whisper.MessageStore
}

func NewNimbusWhisperService() (statusprototypes.WhisperInterface, error) {
	C.NimMain()
	fmt.Println(C.nimbus_start(30306))

	peer1 := "enode://2d3e27d7846564f9b964308038dfadd4076e4373ac938e020708ad8819fd4fd90e5eb8314140768f782db704cb313b60707b968f8b61108a6fecd705b041746d@192.168.0.33:30303"
	peer2 := "enode://4ea35352702027984a13274f241a56a47854a7fd4b3ba674a596cff917d3c825506431cf149f9f2312a293bb7c2b1cca55db742027090916d01529fe0729643b@206.189.243.178:443"

	peer3 := "enode://94d2403d0c55b5c1627eb032c4c6ea8d30b523ae84661aafa18c539ce3af3f114a5bfe1a3cde7776988a6ab2906169dca8ce6a79e32d30c445629b24e6f59e0a@0.0.0.0:30303"
	fmt.Println(C.nimbus_add_peer(C.CString(peer1)))
	fmt.Println(C.nimbus_add_peer(C.CString(peer2)))
	fmt.Println(C.nimbus_add_peer(C.CString(peer3)))

	go poll()

	return &NimbusWhisperService{}, nil
}

func (n *NimbusWhisperService) NewMessageStore() whisper.MessageStore {
	if n.messageStoreFabric != nil {
		return n.messageStoreFabric()
	}
	return whisper.NewMemoryMessageStore()
}

// func (n *NimbusWhisperService) SubscribeEnvelopeEvents(events chan<- whisper.EnvelopeEvent) events.Subscription {

// }

func (n *NimbusWhisperService) AddKeyPair(key *ecdsa.PrivateKey) (string, error) {
	//C.nimbus_add_keypair(C.CString(key))
	return "", nil
}

func (n *NimbusWhisperService) AddSymKeyDirect(key []byte) (string, error) {
	//C.nimbus_add_symkey(C.CString(key))
	return "", nil
}

func (n *NimbusWhisperService) AddSymKeyFromPassword(password string) (string, error) {
	//C.nimbus_add_symkey_from_password(C.CString(key))
	return "", nil
}

func (n *NimbusWhisperService) DeleteSymKey(id string) bool {
	//C.nimbus_delete_symkey(C.CString(id))
	return false
}

func (n *NimbusWhisperService) GetSymKey(id string) ([]byte, error) {
	//C.nimbus_get_symkey(C.CString(id))
	return nil, nil
}

func (n *NimbusWhisperService) Subscribe(f *whisper.Filter) (string, error) { // TODO: Replace whisper.Filter type
	//C.nimbus_subscribe(f.KeySym, f.KeyAsym, topics)
	return "", nil
}

func (n *NimbusWhisperService) GetFilter(id string) *whisper.Filter {
	//C.nimbus_get_filter(C.CString(id))
	return nil
}

func (n *NimbusWhisperService) Unsubscribe(id string) error {
	//C.nimbus_unsubscribe(C.CString(id))
	return nil
}
