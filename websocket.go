package goproxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"

	"github.com/gorilla/websocket"
)

type ResponseHijack struct {
	*httptest.ResponseRecorder
	br   *bufio.Reader
	conn *tls.Conn
}

func (r *ResponseHijack) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	rw := bufio.NewReadWriter(r.br, bufio.NewWriter(r.conn))
	return r.conn, rw, nil
}

func (proxy *ProxyHttpServer) handeWebsocket(ctx *ProxyCtx, req *http.Request, br *bufio.Reader, rawClientTls *tls.Conn) {
	rw := &ResponseHijack{httptest.NewRecorder(), br, rawClientTls}
	requestHeader := http.Header{}
	if origin := req.Header.Get("Origin"); origin != "" {
		requestHeader.Add("Origin", origin)
	}
	for _, prot := range req.Header[http.CanonicalHeaderKey("Sec-WebSocket-Protocol")] {
		requestHeader.Add("Sec-WebSocket-Protocol", prot)
	}
	for _, cookie := range req.Header[http.CanonicalHeaderKey("Cookie")] {
		requestHeader.Add("Cookie", cookie)
	}
	for _, target := range req.Header[http.CanonicalHeaderKey("X-Wise-Target")] {
		requestHeader.Add("X-Wise-Target", target)
	}

	req.URL.Scheme = "wss"
	req.URL.Host = req.Host
	url := req.URL.String()
	ctx.Logf("websocket: connect to %s", url)
	connBackend, resp, err := websocket.DefaultDialer.Dial(url, requestHeader)
	if err != nil {
		ctx.Warnf("websocket: dial error %s", err)
		return
	}
	defer connBackend.Close()
	upgradeHeader := http.Header{}
	if hdr := resp.Header.Get("Sec-Websocket-Protocol"); hdr != "" {
		upgradeHeader.Set("Sec-Websocket-Protocol", hdr)
	}
	if hdr := resp.Header.Get("Set-Cookie"); hdr != "" {
		upgradeHeader.Set("Set-Cookie", hdr)
	}
	connPub, err := websocket.Upgrade(rw, req, upgradeHeader, 1024, 1024)
	if err != nil {
		ctx.Warnf("websocket: can not upgrade %s", err)
	}
	errClient := make(chan error, 1)
	errBackend := make(chan error, 1)
	replicateWebsocketConn := func(dst, src *websocket.Conn, errc chan error) {
		for {
			msgType, msg, err := src.ReadMessage()
			if err != nil {
				m := websocket.FormatCloseMessage(websocket.CloseNormalClosure, fmt.Sprintf("%v", err))
				if e, ok := err.(*websocket.CloseError); ok {
					if e.Code != websocket.CloseNoStatusReceived {
						m = websocket.FormatCloseMessage(e.Code, e.Text)
					}
				}
				errc <- err
				dst.WriteMessage(websocket.CloseMessage, m)
				break
			}
			err = dst.WriteMessage(msgType, msg)
			if err != nil {
				errc <- err
				break
			}
		}
	}

	go replicateWebsocketConn(connPub, connBackend, errClient)
	go replicateWebsocketConn(connBackend, connPub, errBackend)

	var message string
	select {
	case err = <-errClient:
		message = "websocket: Error when copying from backend to client: %v"
	case err = <-errBackend:
		message = "websocket: Error when copying from client to backend: %v"

	}
	if e, ok := err.(*websocket.CloseError); !ok || e.Code == websocket.CloseAbnormalClosure {
		ctx.Warnf(message, err)
	}
	return
}
