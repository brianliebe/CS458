#include <iostream>
#include <fstream>

using namespace std;

int **create_mapping(int seed) {
	int *encrypt = new int[26];
	int *decrypt = new int[26];
	int **both = new int*[2];
	int check[26];
	int matches_found = 0;

	srand(seed);

	// Set each value to 0
	for (int i = 0; i < 26; i++) {
		check[i] = 0;
	}

	// Generate a random number 0-26 and check to make sure it hasn't been chosen yet
	while (matches_found < 26) {
		int random = rand() % 26;
		if (matches_found != random && check[random] == 0) {
			check[random] = 1;
			encrypt[matches_found] = random;
			decrypt[random] = matches_found;
			matches_found++;
		}
		else {
			// If 0-24 have been assigned but 25 is left, the only valid value is 25 (which can't happen)
			// To easily resolve this, we just reset the entire thing and try again
			if (matches_found == 25) {
				for (int i = 0; i < 26; i++) {
					check[i] = 0;
				}
				matches_found = 0;
			}
		}
	}
	both[0] = encrypt;
	both[1] = decrypt;
	return both;
}

int main (int, char **argv) {
	char *input = argv[1];
	char *output = argv[2];
	char c;
	int seed = atoi(argv[3]);
	int encrypt = atoi(argv[4]);

	// Create in/out streams
	ifstream in(input);
	ofstream out(output);

	int **map = create_mapping(seed);

	// Encrypt or Decrypt
	if (encrypt) {
		while (in >> c) {
			// Output the mapped value from the encrypt array
			int val = c - 97;
			out << (char)(map[0][val] + 97);
		}
		out << endl;
	}
	else {
		while (in >> c) {
			// Output the mapped value from the decrypt array
			int val = c - 97;
			out << (char)(map[1][val] + 97);
		}
		out << endl;
	}

	// Print out the pairs
	for (int i = 0; i < 26; i++) {
		if (i == 25) cout << (char)(i + 97) << "-" << (char)(map[0][i] + 97) << endl;
		else cout << (char)(i + 97) << "-" << (char)(map[0][i] + 97) << ", ";
	}

	// Free all allocated memory
	free(map[0]);
	free(map[1]);
	free(map);
	return 0;
}
