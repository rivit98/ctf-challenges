#include "libc.h"
#include <stdint.h>

#define MAX_COLOR_LEN 0xe0
#define MAX_NAME_LEN 0x20
#define PLAYER_BOT 0
#define PLAYER_USER 1

typedef struct {
  const char *name;
  const char *color;
  uint32_t score;
} player_t;

typedef struct {
  memory_pool_t memory_pool;
  int debug_mode;
} program_state_t;

const size_t max_color_len = MAX_COLOR_LEN;

void dump_player(player_t *player) {
  char score_str[0x20] = {};
  itoa(player->score, score_str);
  print("score: ");
  print(score_str);
  print("\n");
}

void set_score(program_state_t *state, player_t *player) {
  player->score = (((uint64_t)player & 0xFFFFFFFFF00) >> 16) << 1;
  char *p = (char *)player->name;
  while (p && *p++) {
    player->score += *p;
  }

  if (state->debug_mode == 1) {
    dump_player(player);
  }
}

void user_setup(program_state_t *state, player_t *player) {
  char name[MAX_NAME_LEN] = {};
  char *color = malloc(&state->memory_pool, max_color_len);
  memset(color, 0, max_color_len);

  while (1) {
    print("Nick: ");
    if (read(STDIN_FILENO, name, max_color_len - 1) <= 0) { // obvious bug...
      print("Invalid name, try again\n");
      continue;
    }

    set_score(state, player);

    print("Color: ");
    if (read(STDIN_FILENO, color, max_color_len - 1) <= 0) {
      print("Invalid color, try again\n");
      if (state->debug_mode == 1) {
        dump_player(player);
      }
      continue;
    }
    break;
  }

  rtrim(name);
  rtrim(color);
  player->name = strdup(&state->memory_pool, name);
  player->color = color;
  print("Battle begins!\n");
}

void bot_setup(program_state_t *state, player_t *player) {
  player->name = "Rick";
  player->color = "Blue";
  set_score(state, player);
}

void battle(program_state_t *state, player_t **players) {
  player_t *user = players[PLAYER_USER];
  player_t *bot = players[PLAYER_BOT];
  print(user->name);
  print(" [");
  print(user->color);
  print("]");
  print(" vs ");
  print(bot->name);
  print(" [");
  print(bot->color);
  print("]\n");

  if (bot->score < user->score) {
    print("You won!\n");
  } else {
    print("Try again\n");
  }
}

void main() {
  const int heap_size = 0x1000;
  void *addr = mmap(NULL, heap_size, PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

  memory_pool_t pool = {.alloc_ptr = addr,
                       };

  player_t *players[2] = {malloc(&pool, sizeof(player_t)),
                          malloc(&pool, sizeof(player_t))};

  program_state_t ctx = {.memory_pool = pool, .debug_mode = 0};

  bot_setup(&ctx, players[PLAYER_BOT]);
  user_setup(&ctx, players[PLAYER_USER]);
  battle(&ctx, players);
}

__attribute__((noreturn)) void _start(void) {
  __asm__ volatile("andq $-16, %rsp\n"
                   "call main\n");

  exit(EXIT_SUCCESS);
}
