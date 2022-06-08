package main

// User - модель данных в БД
// guid из параметров запроса 1 маршрута, rts - хеши refresh токенов
type User struct {
	GUID string `json:"guid"`
	//Rts  []([]byte) `json:"rts"`
	Rts []string `json:"rts"`
}

// RemoveAt убирает элемент Rts с индексом i
func (u *User) RemoveAt(i int) {
	u.Rts[i] = u.Rts[len(u.Rts)-1]
	u.Rts = u.Rts[:len(u.Rts)-1]
}
