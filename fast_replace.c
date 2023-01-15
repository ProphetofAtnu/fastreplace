#include "include/emacs-module.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include <stdio.h>

int plugin_is_GPL_compatible;

#define MAKE_EMACS_CONVERTER(deleter, type)                                    \
  static void __wrap_##deleter(void *__arg) { deleter((type *)__arg); }        \
  static emacs_value emacs_value_from_##type(emacs_env *env, type *__arg) {    \
    return env->make_user_ptr(env, &__wrap_##deleter, __arg);                  \
  }                                                                            \
  static type *emacs_value_into_##type(emacs_env *env, emacs_value __arg) {    \
    if (env->is_not_nil(env, env->funcall(env, env->intern(env, "user-ptrp"),  \
                                          1, (emacs_value[]){__arg})))         \
      return env->get_user_ptr(env, __arg);                                    \
    return NULL;                                                               \
  }

#define INTERN(__env, __sym) __env->intern(__env, __sym)

#define FUNCALL(__env, __fsym, __argc, __argv)                                 \
  __env->funcall(__env, __env->intern(__env, #__fsym), __argc, __argv)

#define NIL(__env) __env->intern(env, "nil")

#define IS_NOT_NIL(__env, __arg) env->is_not_nil(__env, __arg)

static void free_match_iterator_from_emacs(void *mi);

MAKE_EMACS_CONVERTER(pcre2_code_free, pcre2_code);
MAKE_EMACS_CONVERTER(pcre2_match_data_free, pcre2_match_data);

struct match_iterator_state {
  pcre2_code *code;
  pcre2_match_data *match_data;
  size_t *ovector;
  size_t start_offset;
  uint32_t options;
  short crlf_is_newline;
  unsigned char *string;
  size_t len;
};

typedef struct match_iterator_state struct_match_iterator_state;

MAKE_EMACS_CONVERTER(free_match_iterator_from_emacs,
                     struct_match_iterator_state);

struct code_compile_error {
  int errornumber;
  PCRE2_SIZE erroroffset;
};

static struct code_compile_error
initialize_match_iterator(struct match_iterator_state *state, PCRE2_SPTR ptr,
                          bool no_zero) {
  struct code_compile_error cce = {0};
  if (!no_zero) {
    memset(state, 0, sizeof(struct match_iterator_state));
  } else {
    if (state->code) {
      pcre2_code_free(state->code);
      state->code = NULL;
    }
    if (state->match_data) {
      pcre2_match_data_free(state->match_data);
      state->code = NULL;
    }
    state->ovector = NULL;
  }

  pcre2_code *re = pcre2_compile(
      (PCRE2_SPTR)ptr,       /* the pattern */
      PCRE2_ZERO_TERMINATED, /* indicates pattern is zero-terminated */
      0,                     /* default options */
      &cce.errornumber,      /* for error number */
      &cce.erroroffset,      /* for error offset */
      NULL);                 /* use default compile context */

  if (re) {
    /* printf("COMP RESULT: %d\n", pcre2_jit_compile(re, PCRE2_JIT_COMPLETE));
     */
    pcre2_jit_compile(re, PCRE2_JIT_COMPLETE);
    state->match_data = pcre2_match_data_create_from_pattern(re, NULL);
    state->ovector = pcre2_get_ovector_pointer(state->match_data);
  }
  state->code = re;

  return cce;
}

static void release_match_iterator(struct match_iterator_state *state) {
  /* Release the code */
  if (state->code) {
    pcre2_code_free(state->code);
    state->code = NULL;
  }
  /* Release the match data and remove invalidated pointers */
  if (state->match_data) {
    pcre2_match_data_free(state->match_data);
    state->match_data = NULL;
    state->ovector = NULL;
  }
  /* Release the string */
  if (state->string) {
    free(state->string);
    state->string = NULL;
    state->len = 0;
  }
}

static void free_match_iterator_from_emacs(void *mi) {
  if (mi == NULL)
    return;
  release_match_iterator(mi);
  free(mi);
}

static inline void reset_match_iterator(struct match_iterator_state *state) {
  if (state->ovector == NULL)
    state->ovector = pcre2_get_ovector_pointer(state->match_data);
  size_t ovec_size = pcre2_get_ovector_count(state->match_data);
  state->start_offset = 0;
  state->ovector[1] = 0;
}

static inline void
release_match_iterator_target(struct match_iterator_state *state) {
  if (state->string != NULL) {
    free(state->string);
    state->string = NULL;
    state->len = 0;
  }
  reset_match_iterator(state);
}

static inline void set_match_iterator_target(struct match_iterator_state *state,
                                             unsigned char *string,
                                             size_t length) {
  release_match_iterator_target(state);
  state->string = string;
  state->len = length;
}

static inline int next_for_match_iterator(struct match_iterator_state *state) {
  int rc;
  if (state->string == NULL)
    return 0;
  if (state->ovector == NULL)
    state->ovector = pcre2_get_ovector_pointer(state->match_data);
retry:
  state->start_offset = state->ovector[1];
  /* Check for empty match */
  if (state->ovector[0] == state->ovector[1]) {
    if (state->ovector[0] == state->len)
      return 0;
    state->options = PCRE2_NOTEMPTY_ATSTART | PCRE2_ANCHORED;
  }

  rc = pcre2_match(state->code,         /* the compiled pattern */
                   state->string,       /* the subject string */
                   state->len,          /* the length of the subject */
                   state->start_offset, /* starting offset in the subject */
                   state->options,      /* options */
                   state->match_data,   /* block for storing the result */
                   NULL);               /* use default match context */
  if (rc == PCRE2_ERROR_NOMATCH) {
    /* No options and no match means we're done */
    if (state->options == 0)
      return 0;
    state->ovector[1] = state->start_offset + 1;
    if (state->ovector[1] < state->len)
      goto retry;
  }
  return rc;
}

static inline int emacs_extract_string(emacs_env *env, emacs_value arg,
                                       char **out, intmax_t *len) {
  if (!IS_NOT_NIL(env, FUNCALL(env, stringp, 1, (emacs_value[]){arg}))) {
    return -1;
  }
  char *output = NULL;

  intmax_t alen;
  env->copy_string_contents(env, arg, output, &alen);
  output = malloc(alen);
  env->copy_string_contents(env, arg, output, &alen);

  *out = output;
  *len = alen;
  return 0;
}

static inline int populate_match_arguments(emacs_env *env, emacs_value args[],
                                           pcre2_code **code,
                                           unsigned char **nsub, size_t *xlen,
                                           pcre2_match_data **md,
                                           intmax_t *offset) {
  ptrdiff_t slen = 256;

  if ((*code = emacs_value_into_pcre2_code(env, args[0])) == NULL)
    return -1;
  /* return NIL(env); */

  if (!IS_NOT_NIL(env, FUNCALL(env, integerp, 1, args + 2))) {
    return -3;
  }
  if (emacs_extract_string(env, args[1], (char **)nsub, &slen) < 0) {
    return -2;
  }

  *xlen = slen;
  *md = pcre2_match_data_create_from_pattern(*code, NULL);
  /* *nsub = (unsigned char *)subject; */
  *offset = env->extract_integer(env, args[2]);
  return 0;
}

static inline int
populate_match_state_from_arguments(emacs_env *env, emacs_value args[],
                                    struct match_iterator_state *state) {

  return populate_match_arguments(env, args, &state->code, &state->string,
                                  &state->len, &state->match_data,
                                  (intmax_t *)&state->start_offset);
}

static inline void
release_static_populated_match_state(struct match_iterator_state *state) {
  release_match_iterator_target(state);
  pcre2_match_data_free(state->match_data);
  state->match_data = NULL;
}

static inline emacs_value
convert_ovec_into_emacs_vector(emacs_env *env, size_t *ovec, size_t cnt) {

  emacs_value fargs[] = {env->make_integer(env, cnt * 2),
                         env->intern(env, "nil")};

  emacs_value offsets = NIL(env);
  // clang-format off
  offsets = FUNCALL(env, make-vector, 2, fargs);
  // clang-format on

  size_t start_index = 0;
  for (size_t i = 0; i < cnt; i++) {
    start_index = i * 2;
    env->vec_set(env, offsets, start_index,
                 env->make_integer(env, ovec[start_index]));
    env->vec_set(env, offsets, start_index + 1,
                 env->make_integer(env, ovec[start_index + 1]));
  }
  return offsets;
}

static inline emacs_value handle_regex_error(emacs_env *env, int errornumber,
                                             PCRE2_SIZE erroroffset) {
  PCRE2_UCHAR buffer[256];
  pcre2_get_error_message(errornumber, buffer, sizeof(buffer));
  printf("PCRE2 compilation failed at offset %d: %s\n", (int)erroroffset,
         buffer);
  return env->intern(env, "nil");
}

static inline emacs_value handle_match_error(emacs_env *env, int rc) {
  if (rc < 0) {
    switch (rc) {
    case PCRE2_ERROR_NOMATCH:
      printf("No match\n");
      break;
    /*
    Handle other special cases if you like
    */
    case 0:
      printf("ovector was not big enough for all the captured substrings\n");
    default:
      printf("Matching error %d\n", rc);
      break;
    }
  }
  return NIL(env);
}

// Frontend emacs module code
static emacs_value emacs_create_match_iterator(emacs_env *env, ptrdiff_t nargs,
                                               emacs_value args[], void *data) {
  struct_match_iterator_state *state =
      malloc(sizeof(struct_match_iterator_state));
  intmax_t length;
  char *string;
  char *target_string;

  if (emacs_extract_string(env, args[0], &string, &length) < 0) {
    free(state);
    return NIL(env);
  }

  initialize_match_iterator(state, (PCRE2_SPTR)string, false);
  free(string);

  if (nargs > 1) {
    if (emacs_extract_string(env, args[1], &target_string, &length) < 0) {
      free(state);
      return NIL(env);
    }
    set_match_iterator_target(state, (unsigned char *)target_string, length);
  }
  return emacs_value_from_struct_match_iterator_state(env, state);
}

static emacs_value emacs_match_iterator_set_regex(emacs_env *env,
                                                  ptrdiff_t nargs,
                                                  emacs_value args[],
                                                  void *data) {
  struct_match_iterator_state *state =
      emacs_value_into_struct_match_iterator_state(env, args[0]);
  intmax_t length;
  char *string;
  if (emacs_extract_string(env, args[1], &string, &length) < 0) {
    return NIL(env);
  }

  initialize_match_iterator(state, (PCRE2_SPTR)string, true);
  free(string);
  return emacs_value_from_struct_match_iterator_state(env, state);
}

static emacs_value emacs_match_iterator_has_target(emacs_env *env,
                                                   ptrdiff_t nargs,
                                                   emacs_value args[],
                                                   void *data) {
  struct_match_iterator_state *state =
      emacs_value_into_struct_match_iterator_state(env, args[0]);

  if (state->string == NULL) {
    return NIL(env);
  } else {
    return env->intern(env, "t");
  }
}

static emacs_value emacs_match_iterator_set_target(emacs_env *env,
                                                   ptrdiff_t nargs,
                                                   emacs_value args[],
                                                   void *data) {
  intmax_t length;
  char *string;
  struct_match_iterator_state *state =
      emacs_value_into_struct_match_iterator_state(env, args[0]);

  if (emacs_extract_string(env, args[1], &string, &length) < 0) {
    return NIL(env);
  }

  set_match_iterator_target(state, (unsigned char *)string, length);

  return env->intern(env, "t");
}

static emacs_value emacs_match_iterator_clear_target(emacs_env *env,
                                                     ptrdiff_t nargs,
                                                     emacs_value args[],
                                                     void *data) {
  struct_match_iterator_state *state =
      emacs_value_into_struct_match_iterator_state(env, args[0]);

  release_match_iterator_target(state);
  return NIL(env);
}

static emacs_value emacs_match_iterator_get_target(emacs_env *env,
                                                   ptrdiff_t nargs,
                                                   emacs_value args[],
                                                   void *data) {
  struct_match_iterator_state *state =
      emacs_value_into_struct_match_iterator_state(env, args[0]);

  if (state->string) {
    return env->make_string(env, (const char *)state->string, state->len);
  } else {
    return NIL(env);
  }
}

static emacs_value emacs_match_iterator_advance(emacs_env *env, ptrdiff_t nargs,
                                                emacs_value args[],
                                                void *data) {
  struct_match_iterator_state *state =
      emacs_value_into_struct_match_iterator_state(env, args[0]);
  if (next_for_match_iterator(state) > 0) {
    return env->intern(env, "t");
  } else {
    return NIL(env);
  }
}

static emacs_value emacs_match_iterator_offset_vector(emacs_env *env,
                                                      ptrdiff_t nargs,
                                                      emacs_value args[],
                                                      void *data) {
  struct_match_iterator_state *state =
      emacs_value_into_struct_match_iterator_state(env, args[0]);

  if (state->match_data) {
    return convert_ovec_into_emacs_vector(
        env, pcre2_get_ovector_pointer(state->match_data),
        pcre2_get_ovector_count(state->match_data));
  } else {
    return NULL;
  }
}

static emacs_value emacs_match_iterator_get_all_matches(emacs_env *env,
                                                        ptrdiff_t nargs,
                                                        emacs_value args[],
                                                        void *data) {
  int match_result = 0;
  size_t ovec_size;
  emacs_value result = NIL(env);
  struct_match_iterator_state *state =
      emacs_value_into_struct_match_iterator_state(env, args[0]);

  reset_match_iterator(state);

  ovec_size = pcre2_get_ovector_count(state->match_data);

  while ((match_result = next_for_match_iterator(state)) > 0) {
    emacs_value fargs[] = {
        convert_ovec_into_emacs_vector(env, state->ovector, ovec_size), result};
    result = FUNCALL(env, cons, 2, fargs);
  }

  if (env->is_not_nil(env, result))
    result = FUNCALL(env, nreverse, 1, (emacs_value[]){result});
  /* release_match_iterator_target(&state); */
  return result;
}

static emacs_value demo(emacs_env *env, ptrdiff_t nargs, emacs_value args[],
                        void *data) {
  return env->intern(env, "t");
}

/* Bind NAME to FUN.  */
static void bind_function(emacs_env *env, const char *name, emacs_value Sfun) {
  emacs_value Qfset = env->intern(env, "fset");
  emacs_value Qsym = env->intern(env, name);
  emacs_value args[] = {Qsym, Sfun};

  env->funcall(env, Qfset, 2, args);
}

/* Provide FEATURE to Emacs.  */
static void provide(emacs_env *env, const char *feature) {
  emacs_value Qfeat = env->intern(env, feature);
  emacs_value Qprovide = env->intern(env, "provide");
  emacs_value args[] = {Qfeat};

  env->funcall(env, Qprovide, 1, args);
}

int emacs_module_init(struct emacs_runtime *ert) {
  emacs_env *env = ert->get_environment(ert);
  bind_function(
      env, "fast-replace-pcre2-create-match-iterator",
      env->make_function(env, 1, 2, emacs_create_match_iterator, "doc", NULL));
  bind_function(env, "fast-replace-pcre2-match-iterator-has-target",
                env->make_function(env, 1, 1, emacs_match_iterator_has_target,
                                   "doc", NULL));
  bind_function(env, "fast-replace-pcre2-match-iterator-set-target",
                env->make_function(env, 2, 2, emacs_match_iterator_set_target,
                                   "doc", NULL));
  bind_function(env, "fast-replace-pcre2-match-iterator-set-regex",
                env->make_function(env, 2, 2, emacs_match_iterator_set_regex,
                                   "doc", NULL));
  bind_function(env, "fast-replace-pcre2-match-iterator-clear-target",
                env->make_function(env, 1, 1, emacs_match_iterator_clear_target,
                                   "doc", NULL));
  bind_function(env, "fast-replace-pcre2-match-iterator-get-target",
                env->make_function(env, 1, 1, emacs_match_iterator_get_target,
                                   "doc", NULL));
  bind_function(
      env, "fast-replace-pcre2-match-iterator-advance",
      env->make_function(env, 1, 1, emacs_match_iterator_advance, "doc", NULL));
  bind_function(env, "fast-replace-pcre2-match-iterator-get-offset-vector",
                env->make_function(env, 1, 1,
                                   emacs_match_iterator_offset_vector, "doc",
                                   NULL));
  bind_function(env, "fast-replace-pcre2-match-iterator-all-matches",
                env->make_function(env, 1, 1,
                                   emacs_match_iterator_get_all_matches, "doc",
                                   NULL));
  provide(env, "fastreplace");
  return 0;
}
