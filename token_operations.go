
import (
	"errors"
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

// jwt.StandardClaims для exp и jti
type сlaims struct {
	UserID string `json:"uid"`
	jwt.StandardClaims
}

func getClaims(c *http.Cookie) (*сlaims, error) {
	tknStr := c.Value
	claims := &сlaims{}

	// парс JWT в claims
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		// проверка, что токен подписан с SHA
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			//fmt.Printf("sign method unexpected: %v\n", token.Header["alg"])
			return nil, fmt.Errorf("Неожиданный алгоритм подписи: %v", token.Header["alg"])
		}

		return jwtKey, nil
	})
	if err != nil {
		//fmt.Printf("parse err: %v", err)
		return nil, err
	}
	if !tkn.Valid {
		//fmt.Println("tk not valid")
		return claims, errors.New("Token is not valid")
	}

	return claims, nil
}

//Операция переворачивания строки
/*	Зачем: я выбрал jwt для refresh токенов, но возникла проблема с bcrypt:
	алгоритм генерировал одинаковый salt для любых токенов одного пользователя,
	и считал, что все хеши в БД подходят для данного токена
	и таким образом всегда удалялся 1-й встретившийся токен пользователя.
	Это не проблема реализации: я проверял на https://bcrypt-generator.com/,
	и bcrypt действительно так работает с jwt.
	Возможно это из-за одинакового начала; по крайней мере, переворачивая строку
	и помещая очень различающуюся подпись в начало, я решаю эту проблему
	(без особого влияния на производительность)
	Увеличивать цену
*/
func reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}
