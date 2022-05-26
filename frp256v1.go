// Parameters for the FRP256v1 Elliptic curve
package frp256v1

import (
	"crypto/elliptic"
	"math/big"
	"sync"
)

var initonce sync.Once
var frp256v1 *elliptic.CurveParams

func initFRP256v1() {
	frp256v1 = new(elliptic.CurveParams)
	frp256v1.P, _ = new(big.Int).SetString("f1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c03", 16)
	frp256v1.N, _ = new(big.Int).SetString("f1fd178c0b3ad58f10126de8ce42435b53dc67e140d2bf941ffdd459c6d655e1", 16)
	frp256v1.B, _ = new(big.Int).SetString("ee353fca5428a9300d4aba754a44c00fdfec0c9ae4b1a1803075ed967b7bb73f", 16)
	frp256v1.Gx, _ = new(big.Int).SetString("b6b3d4c356c139eb31183d4749d423958c27d2dcaf98b70164c97a2dd98f5cff", 16)
	frp256v1.Gy, _ = new(big.Int).SetString("6142e0f7c8b204911f9271f0f3ecef8c2701c307e8e4c9e183115a1554062cfb", 16)
	frp256v1.BitSize = 256
}

func FRP256v1() elliptic.Curve {
	initonce.Do(initFRP256v1)
	return frp256v1
}
