/*
 *
 * Small program to practically demonstrate the collision attack on md5 hashes.
 * This code is a complement to an academic work. Its use is purely educational.
 *
 * gcc md5_crack.c -o md5_crack -pthread -lssl -lcrypto
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <openssl/md5.h>
#include <time.h>

#define MAX_WORD_LEN 256
#define MAX_HASH_LEN 33

typedef struct {
    char **words;
    char **hashes;
    unsigned num_words;
    unsigned num_hashes;
    int thread_id;
    int num_threads;
    FILE *output_file;
    pthread_mutex_t *file_mutex;
    int *match_count;
} thread_conf;

void compute_md5(const char *str, char *md5_string) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((unsigned char *)str, strlen(str), digest);

    for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
        sprintf(&md5_string[i * 2], "%02x", digest[i]);

    md5_string[32] = '\0';
}

void *compare_hashes_thread(void *arg) {
    thread_conf *data = (thread_conf *)arg;
    char computed_hash[MAX_HASH_LEN];

    for (int i = data->thread_id; i < data->num_words; i += data->num_threads) {
        compute_md5(data->words[i], computed_hash);

        for (int j = 0; j < data->num_hashes; j++) {
            if (strcmp(computed_hash, data->hashes[j]) == 0) {
                pthread_mutex_lock(data->file_mutex);
                (*data->match_count)++;
                printf("[Thread %d] Match found! Word: %s | Hash: %s\n",
                    data->thread_id, data->words[i], computed_hash);
                if (data->output_file) {
                    fprintf(data->output_file, "Match: %s -> %s\n", data->words[i], computed_hash);
                }
                pthread_mutex_unlock(data->file_mutex);
            }
        }
    }

    return NULL;
}

char **load_list_from_file(const char *filename, unsigned *count) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open file");
        exit(EXIT_FAILURE);
    }

    char **list = malloc(sizeof(char *) * 10000);
    char buffer[MAX_WORD_LEN];
    unsigned i = 0;

    while (fgets(buffer, sizeof(buffer), file)) {
        buffer[strcspn(buffer, "\r\n")] = '\0';
        list[i] = strdup(buffer);
        i++;
    }

    fclose(file);
    *count = i;
    return list;
}

int main(int argc, char *argv[]) {
    if (argc < 4 || argc > 5) {
        fprintf(stderr, "Usage: %s <wordlist.txt> <hashes.txt> <num_threads> [output.txt]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    unsigned num_words, num_hashes;
    int num_threads = atoi(argv[3]);
    FILE *output_file = NULL;
    pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
    int match_count = 0;

    if (argc == 5) {
        output_file = fopen(argv[4], "w");
        if (!output_file) {
            perror("Failed to open output file");
            exit(EXIT_FAILURE);
        }
    }

    char **words = load_list_from_file(argv[1], &num_words);
    char **hashes = load_list_from_file(argv[2], &num_hashes);

    pthread_t threads[num_threads];
    thread_conf configs[num_threads];

    clock_t start = clock();

    for (int i = 0; i < num_threads; i++) {
        configs[i].words = words;
        configs[i].hashes = hashes;
        configs[i].num_words = num_words;
        configs[i].num_hashes = num_hashes;
        configs[i].thread_id = i;
        configs[i].num_threads = num_threads;
        configs[i].output_file = output_file;
        configs[i].file_mutex = &file_mutex;
        configs[i].match_count = &match_count;
        pthread_create(&threads[i], NULL, compare_hashes_thread, &configs[i]);
    }

    for (int i = 0; i < num_threads; i++) 
        pthread_join(threads[i], NULL);
    
    clock_t end = clock();
    double elapsed_time = (double)(end - start) / CLOCKS_PER_SEC;

    printf("\nExecution time: %.2f seconds\n", elapsed_time);
    printf("Total matches found: %d\n", match_count);

    if (output_file) fclose(output_file);
    
    for (unsigned i = 0; i < num_words; i++) free(words[i]);
    for (unsigned i = 0; i < num_hashes; i++) free(hashes[i]);
    free(words);
    free(hashes);

    return EXIT_SUCCESS;
}
