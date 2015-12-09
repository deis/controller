package keys

import (
	"encoding/json"
	"fmt"

	"github.com/deis/workflow/client/controller/api"
	"github.com/deis/workflow/client/controller/client"
)

// List keys on a controller.
func List(c *client.Client, results int) ([]api.Key, int, error) {
	body, count, err := c.LimitedRequest("/v2/keys/", results)

	if err != nil {
		return []api.Key{}, -1, err
	}

	var keys []api.Key
	if err = json.Unmarshal([]byte(body), &keys); err != nil {
		return []api.Key{}, -1, err
	}

	return keys, count, nil
}

// New creates a new key.
func New(c *client.Client, id string, pubKey string) (api.Key, error) {
	req := api.KeyCreateRequest{ID: id, Public: pubKey}
	body, err := json.Marshal(req)

	resBody, err := c.BasicRequest("POST", "/v2/keys/", body)

	if err != nil {
		return api.Key{}, err
	}

	key := api.Key{}
	if err = json.Unmarshal([]byte(resBody), &key); err != nil {
		return api.Key{}, err
	}

	return key, nil
}

// Delete a key.
func Delete(c *client.Client, keyID string) error {
	u := fmt.Sprintf("/v2/keys/%s", keyID)

	_, err := c.BasicRequest("DELETE", u, nil)
	return err
}
