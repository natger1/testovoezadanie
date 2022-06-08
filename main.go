package main

import (
	"log"
	"net/http"
	"os"
)

/*
	receive, refresh, remove, removeall - основные 4 маршрута
	extra_access - доп. маршрут для теста правильности обработки токенов
	env_vars - строки для доступа к БД и ключ для шифрования jwt
	token_operaions - операции с jwt токенами
	user - модель пользователя в БД
*/

func main() {
	//1. выдача пары токенов
	http.HandleFunc("/receive", receive)
	//2. обновление access токена на основе refresh токена
	http.HandleFunc("/refresh", refresh)
	//3. удаление заданного токена из БД
	http.HandleFunc("/remove", remove)
	//4.удаление всех токенов из БД
	http.HandleFunc("/removeall", removeAll)
	//дополнительные маршруты для тестирования
	//access - типичный запрос к защищенному ресурсу, не изменяет токены
	http.HandleFunc("/access", accessProtectedResource)

	port := os.Getenv("PORT")
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
