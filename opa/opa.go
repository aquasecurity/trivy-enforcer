// Package opa contains helpers for pushing data into OPA.
package opa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type OPA struct {
	baseURL string
}

func New(url string) *OPA {
	return &OPA{
		baseURL: strings.TrimRight(url, "/"),
	}
}

type input struct {
	Input interface{}
}

type result struct {
	Result []string
}

func (opa *OPA) Eval(ctx context.Context, path string, data interface{}) ([]string, error) {

	if path[0] != '/' {
		return nil, fmt.Errorf("path must start with '/'")
	}

	var buf bytes.Buffer

	body := input{
		Input: data,
	}
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", opa.baseURL+path, &buf)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	var r result
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}

	return r.Result, nil
}

func (opa *OPA) Push(path string, data interface{}) error {

	if path[0] != '/' {
		return fmt.Errorf("path must start with '/'")
	}

	var buf bytes.Buffer

	if err := json.NewEncoder(&buf).Encode(data); err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", opa.baseURL+path, &buf)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	return opa.decodeError(resp)
}

func (opa *OPA) decodeError(resp *http.Response) error {

	if !strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
		return fmt.Errorf("unexpected status code: %v", resp.Status)
	}

	var body struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return err
	}

	return fmt.Errorf("unexpected response code: %v: %v: %v", body.Code, body.Message, resp.Status)
}
