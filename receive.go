package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

// `Первый маршрут выдает пару Access, Refresh токенов
// для пользователя с идентификатором (GUID) указанным в параметре запроса`
func receive(w http.ResponseWriter, r *http.Request) {

	pars, ok := r.URL.Query()["guid"]
	if !ok || len(pars[0]) < 1 {
		w.WriteHeader(http.StatusBadRequest)
		//log.Println("Url Param 'key' is missing")
		return
	}
	var guid string = pars[0]

	//`Refresh токен тип произвольный (jwt), формат передачи base64 (уже в jwt),
	// хранится в базе исключительно в виде bcrypt хеша,
	// должен быть защищен от изменения на стороне клиента и попыток повторного использования (уже в jwt)`

	rtExpiration := time.Now().Add(5 * time.Hour)
	//генерация строки связи двух токенов
	linkBytes := make([]byte, 32)
	_, err := rand.Read(linkBytes)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	for i, b := range linkBytes {
		linkBytes[i] = letters[b%byte(len(letters))]
	}

	rtClaims := &сlaims{
		UserID: guid,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: rtExpiration.Unix(),
			Id:        string(linkBytes),
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS512, rtClaims)
	rtSigned, err := refreshToken.SignedString(jwtKey)
	if err != nil {
		fmt.Printf("rt err: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	rtHashed, err := bcrypt.GenerateFromPassword([]byte(reverse(rtSigned)), bcrypt.DefaultCost)
	rtHashedS := string(rtHashed)
	if err != nil {
		fmt.Printf("rt bcrypt err: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//Подключение к БД
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(
		connString,
	))

	defer func() {
		if err = client.Disconnect(ctx); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}()

	var session mongo.Session
	if session, err = client.StartSession(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err = session.StartTransaction(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err = mongo.WithSession(ctx, session, func(sc mongo.SessionContext) error {
		collection := client.Database("goauth").Collection("users")
		findFilter := bson.M{"guid": guid}
		var result User

		err = collection.FindOne(ctx, findFilter).Decode(&result)
		isNewUser := err == mongo.ErrNoDocuments
		//fmt.Printf("%v; %s -> %v\n", err, result.GUID, result.Rts)
		if err != nil && !isNewUser {
			fmt.Printf("collection find err: %v\n", err)
			return err
		}

		fmt.Printf("inserting: %s\n", rtSigned)
		if isNewUser {
			//newRts := make([]([]byte), 0, 1)
			newRts := make([]string, 0, 1)
			newRts = append(newRts, rtHashedS)
			newUser := User{GUID: guid, Rts: newRts}

			_, err = collection.InsertOne(ctx, newUser)
			if err != nil {
				fmt.Printf("new user insert err: %v\n", err)
				return err
			}
		} else {
			//newRts := make([]([]byte), len(result.Rts), len(result.Rts)+1)
			newRts := make([]string, len(result.Rts), len(result.Rts)+1)
			copy(newRts, result.Rts)
			newRts = append(newRts, rtHashedS)
			newUser := User{GUID: guid, Rts: newRts}
			//TODO без создания структуры тест
			updateFilter := bson.D{
				primitive.E{Key: "$set", Value: bson.D{
					primitive.E{Key: "rts", Value: newUser.Rts}}}}
			_, err = collection.UpdateOne(ctx, findFilter, updateFilter)
			if err != nil {
				fmt.Printf("update err: %v\n", err)
				return err
			}
		}
		return nil
	}); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	session.EndSession(ctx)

	//`Access токен тип JWT, алгоритм SHA512.`
	atExpiration := time.Now().Add(5 * time.Minute)
	atClaims := &сlaims{
		UserID: guid,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: atExpiration.Unix(),
			//jti для связи токенов в паре
			Id: string(linkBytes),
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, atClaims)
	atSigned, err := accessToken.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//куки безопасней, чем storage
	//TODO: csrf
	http.SetCookie(w, &http.Cookie{
		Name:     "at",
		Value:    atSigned,
		Expires:  atExpiration,
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "rt",
		Value:    rtSigned,
		Expires:  rtExpiration,
		HttpOnly: true,
	})
}
