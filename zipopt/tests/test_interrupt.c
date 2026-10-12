/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

/* POSIX SIGINT test: no leftover named temporary or published zip */

#ifndef _POSIX_C_SOURCE
# define _POSIX_C_SOURCE 200809L
#endif /* ifndef _POSIX_C_SOURCE */

#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PREFIX "interrupt-output.zip.zipopt-"

static int
count_temps (void)
{
  DIR *dir = opendir ("build");
  struct dirent *ent;
  int count = 0;

  if (!dir)
    {
      return -1;
    }

  while ((ent = readdir (dir)) != NULL)
    {
      if (strncmp (ent->d_name, PREFIX, strlen (PREFIX)) == 0)
        {
          count++;
        }
    }

  closedir (dir);

  return count;
}

int
main (void)
{
  pid_t pid, done;
  int st, i, found = 0;
  struct timespec nap;
  FILE *f;

  nap.tv_sec = 0;
  nap.tv_nsec = 10000000L;
  remove ("build/interrupt-output.zip");

  if (count_temps () != 0)
    {
      return 2;
    }

  pid = fork ();

  if (pid < 0)
    {
      return 2;
    }

  if (pid == 0)
    {
      signal (SIGINT, SIG_DFL); /* Reset shell-inherited SIG_IGN. */
      f = freopen ("build/test-interrupt.log", "wb", stderr);

      if (!f)
        {
          _exit (120);
        }

      execl ("./zipopt", "zipopt", "--methods=deflate",
             "build/interrupt-structure.zip", "build/interrupt-output.zip",
             (char *)NULL);

      _exit (121);
    }

  for (i = 0; i < 200; i++)
    {
      if (count_temps () > 0)
        {
          found = 1;

          break;
        }

      done = waitpid (pid, &st, WNOHANG);

      if (done == pid)
        {
          break;
        }

      nanosleep (&nap, NULL);
    }

  if (!found)
    {
      kill (pid, SIGTERM);
      waitpid (pid, &st, 0);
      fprintf (stderr, "interrupt fixture ended before temporary appeared\n");

      return 1;
    }

  if (kill (pid, SIGINT) != 0)
    {
      return 2;
    }

  if (waitpid (pid, &st, 0) != pid)
    {
      return 2;
    }

  if (!WIFEXITED (st) || WEXITSTATUS (st) != 130 || count_temps () != 0)
    {
      fprintf (stderr, "SIGINT failed: status=%d temp=%d\n", st,
               count_temps ());

      return 1;
    }

  f = fopen ("build/interrupt-output.zip", "rb");

  if (f)
    {
      fclose (f);
      fprintf (stderr, "SIGINT published a ZIP unexpectedly\n");

      return 1;
    }

  puts ("PASS: SIGINT removes named temporary and does not publish");

  return 0;
}
