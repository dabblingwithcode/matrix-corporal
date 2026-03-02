package policy

import (
	"encoding/json"
	"sync"

	"github.com/sirupsen/logrus"
)

type Store struct {
	logger    *logrus.Logger
	validator *Validator

	policy     *Policy
	lockPolicy sync.RWMutex

	listenerChannels []chan *Policy
	lockListeners    sync.RWMutex
}

func NewStore(
	logger *logrus.Logger,
	validator *Validator,
) *Store {
	return &Store{
		logger:    logger,
		validator: validator,

		listenerChannels: make([]chan *Policy, 0),
	}
}

func (me *Store) Get() *Policy {
	me.lockPolicy.RLock()
	defer me.lockPolicy.RUnlock()

	return me.policy
}

func (me *Store) Set(policy *Policy) error {
	err := me.validator.Validate(policy)
	if err != nil {
		return err
	}

	me.lockPolicy.Lock()
	defer me.lockPolicy.Unlock()

	me.policy = policy

	//TODO: remove after debugging
	if policyJSON, err := json.Marshal(policy); err == nil {
		//TODO: remove after debugging
		me.logger.WithField("policy", string(policyJSON)).Info("New policy received and stored")
	} else {
		//TODO: remove after debugging
		me.logger.WithError(err).Warn("New policy received and stored; could not marshal for debug log")
	}

	for _, channel := range me.listenerChannels {
		// Do it asynchronously. We don't want to block here..
		go func(channel chan *Policy, policy *Policy) {
			channel <- policy
		}(channel, policy)
	}

	return nil
}

func (me *Store) GetNotificationChannel() chan *Policy {
	me.lockListeners.Lock()
	defer me.lockListeners.Unlock()

	channel := make(chan *Policy)

	me.listenerChannels = append(me.listenerChannels, channel)

	return channel
}

func (me *Store) DestroyNotificationChannel(channel chan *Policy) {
	me.lockListeners.Lock()
	defer me.lockListeners.Unlock()

	close(channel)

	remainingListenerChannels := make([]chan *Policy, 0)
	for _, someChannel := range me.listenerChannels {
		if channel != someChannel {
			remainingListenerChannels = append(remainingListenerChannels, someChannel)
		}
	}
	me.listenerChannels = remainingListenerChannels
}
