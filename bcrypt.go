package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	cost      = flag.Int("c", bcrypt.DefaultCost, "cost used to hash password")
	random    = flag.Bool("r", false, "random cost")
	password  = flag.String("p", "", "password to hash")
	match     = flag.Bool("m", false, "match password")
	hashed    = flag.String("h", "", "hashed password to compare")
	randomMax = flag.Int("x", 0, "maximum random cost")
)

func hash(cost int, random bool, randomMax int, password string) (int, bool, string, time.Duration, error) {

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

	start := time.Now()
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return 0, false, "", 0, err
	}
	elapsed := time.Since(start)

	cost, err = bcrypt.Cost(hashedPassword)
	if err != nil {
		return 0, false, "", 0, err
	}

	return cost, random, string(hashedPassword), elapsed, nil
}

func compare(password string, hashedPassword string) (bool, time.Duration, error) {
	start := time.Now()
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return false, 0, err
	}
	elapsed := time.Since(start)
	return true, elapsed, nil
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
		equal, elapsed, err := compare(*password, *hashed)
		if err != nil {
			fmt.Println("error comparing password:", err)
		}
		fmt.Println("PASSWORDS MATCH:", equal)
		fmt.Println("COMPLETED IN:", elapsed)

	default:
		if *password == "" {
			fmt.Println("password is required")
			os.Exit(1)
		}
		c, r, hashed, elapsed, err := hash(*cost, *random, *randomMax, *password)
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
		fmt.Println("COMPLETED IN:", elapsed)

	}
}
