/*
 *
 * Copyright 2023 puzzlesaltclient authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package puzzlesaltclient

import (
	"context"
	"encoding/base64"
	"time"

	pb "github.com/dvaumoron/puzzlesaltservice"
	"golang.org/x/crypto/scrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// those values are not configurable because a change imply a migration of user database.
const n = 1 << 16
const r = 8
const p = 1
const keyLen = 64

type Client struct {
	saltServiceAddr string
}

func Make(saltServiceAddr string) Client {
	return Client{saltServiceAddr: saltServiceAddr}
}

func (c Client) Salt(login string, password string) (string, error) {
	salt, err := c.loadOrGenerate(login)
	if err != nil {
		return "", err
	}

	dk, err := scrypt.Key([]byte(password), []byte(salt), n, r, p, keyLen)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(dk), nil
}

func (c Client) loadOrGenerate(login string) (string, error) {
	conn, err := grpc.Dial(c.saltServiceAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return "", err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	response, err := pb.NewSaltClient(conn).LoadOrGenerate(ctx, &pb.Request{Login: login})
	if err != nil {
		return "", err
	}
	return response.Salt, nil
}
