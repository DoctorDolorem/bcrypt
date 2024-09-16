package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"

	"golang.org/x/crypto/bcrypt"
)

var (
	cost      = flag.Int("c", bcrypt.DefaultCost, "cost of bcrypt")
	random    = flag.Bool("r", false, "random cost of bcrypt")
	password  = flag.String("p", "", "password to hash")
	match     = flag.Bool("m", false, "match password")
	hashed    = flag.String("h", "", "hashed password to compare")
	randomMax = flag.Int("x", 0, "maximum random cost")
)

func hash(cost int, random bool, randomMax int, password string) (int, bool, string, error) {

	if cost < bcrypt.MinCost {
		fmt.Println("COST TOO LOW, SETTING TO MINIMUM COST: 4")
		cost = bcrypt.MinCost
	} else if cost > bcrypt.MaxCost {
		fmt.Println("COST TOO HIGH, SETTING TO MAXIMUM COST: 31")
		cost = bcrypt.MaxCost
	}

	if random {
		if randomMax == 0 {
			cost = rand.Intn(31)
			if cost < bcrypt.MinCost {
				cost = bcrypt.MinCost
			}
		} else if randomMax < bcrypt.MinCost || randomMax > bcrypt.MaxCost {
			fmt.Println("RANDOM MAX COST OUT OF RANGE, SETTING TO 10")
			randomMax = 10
			cost = rand.Intn(randomMax)
			if cost < bcrypt.MinCost {
				cost = bcrypt.MinCost
			}
		} else {
			cost = rand.Intn(randomMax)
			if cost < bcrypt.MinCost {
				cost = bcrypt.MinCost
			}
		}
		fmt.Println("RANDOM COST USED:", cost)
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), cost)

	cost, err := bcrypt.Cost(hashedPassword)
	if err != nil {
		return 0, false, "", err
	}

	return cost, random, string(hashedPassword), nil
}

func compare(password string, hashedPassword string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return false, err
	}
	return true, nil
}

func main() {
	flag.Parse()

	if len(os.Args) == 1 {
		fmt.Printf("hashing: bcrypt -r <random cost> -rm <maximum random cost> -c <cost> -p <password> \n" +
			"matching: bcrypt -m <match> -p <password> -h <hashed_password>\n")
		os.Exit(1)
	}

	switch *match {
	case true:
		if *password == "" || *hashed == "" {
			fmt.Println("password and hash are required")
			os.Exit(1)
		}
		equal, err := compare(*password, *hashed)
		if err != nil {
			fmt.Println("error comparing password:", err)
		}
		fmt.Println("PASSWORDS MATCH:", equal)

	default:
		if *password == "" {
			fmt.Println("password is required")
			os.Exit(1)
		}
		c, r, hashed, err := hash(*cost, *random, *randomMax, *password)
		if err != nil {
			fmt.Println("error hashing password:", err)
		}
		fmt.Println("PASSWORD:", *password)
		if *random {

			fmt.Println("RANDOM:", r)
		} else {
			fmt.Println("COST:", c)
		}

		fmt.Println("HASHED PASSWORD:", hashed)

	}
}
