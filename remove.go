package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

//`Третий маршрут удаляет конкретный Refresh токен из базы`
//удаляется токен, который был дан с запросом
func remove(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("rt")
	rtString := c.Value
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	rtClaims, err := getClaims(c)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	//Прим.: проверка наличия в БД повторяется в 3 функциях и ее можно вынести в отд функцию
	//		 чтобы сделать кож более dry, но тогда взаимодействия с БД будут в неск. транзакций
	//Проверка наличия в БД и удаление при нахождении
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
		findFilter := bson.M{"guid": rtClaims.UserID}
		var result User

		err = collection.FindOne(ctx, findFilter).Decode(&result)
		if err != nil {
			fmt.Printf("collection find err: %v\n", err)
			if err == mongo.ErrNoDocuments {
				w.WriteHeader(http.StatusUnauthorized)
				return err
			}
			w.WriteHeader(http.StatusInternalServerError)
			return err
		}

		var rtIndex int = -1
		for i, hash := range result.Rts {
			//err = bcrypt.CompareHashAndPassword(hash, []byte(rtString))
			err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(reverse(rtString)))
			if err == nil {
				rtIndex = i
				fmt.Printf("confirmed #%d: %s\n", rtIndex, rtString)
				break
			}
		}
		if rtIndex == -1 {
			w.WriteHeader(http.StatusUnauthorized)
			return errors.New("Not found")
		}

		result.RemoveAt(rtIndex)
		//fmt.Printf("newRts: %s\n", newRts)
		newUser := User{GUID: rtClaims.UserID, Rts: result.Rts}

		updateFilter := bson.D{
			primitive.E{Key: "$set", Value: bson.D{
				primitive.E{Key: "rts", Value: newUser.Rts}}}}

		_, err = collection.UpdateOne(ctx, findFilter, updateFilter)
		if err != nil {
			fmt.Printf("update err: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return err
		}

		return nil
	}); err != nil {
		//w.WriteHeader(http.StatusInternalServerError)
		return
	}
	session.EndSession(ctx)

}
