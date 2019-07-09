package publisher

import (
	"database/sql"
	"errors"
	"log"
	"time"
)

const (
	// How often a ticker fires in seconds.
	tickerInterval = 120
	// How often we should publish a contact code in seconds.
	publishInterval = 21600
)

var (
	errNotEnoughTimePassed = errors.New("not enough time passed")
)

type Publisher struct {
	persistence *sqlitePersistence
	notifyCh    chan struct{}
	quit        chan struct{}
}

func New(db *sql.DB) *Publisher {
	return &Publisher{
		persistence: newSQLitePersistence(db),
	}
}

func (p *Publisher) Start() <-chan struct{} {
	p.notifyCh = make(chan struct{})
	p.quit = make(chan struct{})

	go p.tickerLoop()

	return p.notifyCh
}

func (p *Publisher) Stop() {
	select {
	case _, ok := <-p.quit:
		if !ok {
			// channel already closed
			return
		}
	default:
		close(p.quit)
	}
}

func (p *Publisher) tickerLoop() {
	ticker := time.NewTicker(tickerInterval * time.Second)

	go func() {
		for {
			select {
			case <-ticker.C:
				err := p.notify()
				switch err {
				case errNotEnoughTimePassed:
					log.Printf("[Publisher::startTicker] not enough time passed")
				default:
					log.Printf("[Publisher::startTicker] error while sending a contact code: %v", err)
				}
			case <-p.quit:
				ticker.Stop()
				return
			}
		}
	}()
}

func (p *Publisher) notify() error {
	lastPublished, err := p.persistence.lastPublished()
	if err != nil {
		return err
	}

	now := time.Now().Unix()

	if now-lastPublished < publishInterval {
		return errNotEnoughTimePassed
	}

	p.notifyCh <- struct{}{}

	return p.persistence.setLastPublished(now)
}
