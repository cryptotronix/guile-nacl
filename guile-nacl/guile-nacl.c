/* -*- mode: c; c-file-style: "gnu" -*- */
/* guile-nacl
 * Copyright (C) 2018 Cryptotronix
 *
 * guile-nacl.c: NaCl for Guile
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this program; if not, contact:
 *
 * Free Software Foundation, Inc.     Voice:  +1-617-542-5942
 * 51 Franklin St, Fifth Floor        Fax:    +1-617-542-2652
 * Boston, MA  02110-1301,  USA       gnu@gnu.org
 */

#include <libguile.h>
#include <sodium.h>
#include <assert.h>

#include "guile-nacl.h"


SCM_DEFINE (scm_nacl_rand_buf, "nacl-rand-buf", 1, 0, 0,
            (SCM len),
            "Returns a random buffer of length @var{len}.")
#define FUNC_NAME s_scm_nacl_rand_buf
{
  SCM_VALIDATE_NUMBER(1,len);
  SCM buf = scm_c_make_bytevector (scm_to_size_t (len));
  randombytes_buf (SCM_BYTEVECTOR_CONTENTS (buf), scm_to_size_t (len));

  return buf;
}
#undef FUNC_NAME

static int
symbol_to_varaint (SCM style)
{
  int variant = -1;
  if (SCM_UNBNDP (style))
    {
      variant = sodium_base64_VARIANT_ORIGINAL;
    }
  else if (scm_is_true
           (scm_eq_p (style, scm_from_locale_symbol("VARIANT-ORIGINAL"))))
    {
      variant = sodium_base64_VARIANT_ORIGINAL;
    }
  else if (scm_is_true
           (scm_eq_p (style, scm_from_locale_symbol("VARIANT-ORIGINAL-NO-PADDING"))))
    {
      variant = sodium_base64_VARIANT_ORIGINAL_NO_PADDING;
    }
  else if (scm_is_true
           (scm_eq_p (style, scm_from_locale_symbol("VARIANT-URLSAFE"))))
    {
      variant = sodium_base64_VARIANT_URLSAFE;
    }
  else if (scm_is_true
           (scm_eq_p (style, scm_from_locale_symbol("VARIANT-URLSAFE-NO-PADDING"))))
    {
      variant = sodium_base64_VARIANT_URLSAFE_NO_PADDING;
    }

  return variant;
}

SCM_DEFINE (scm_nacl_b64_encode, "nacl-encode-base64", 1, 1, 0,
            (SCM buf, SCM style),
            "Returns a base64 encoded string in the @var{style} provided")
#define FUNC_NAME s_scm_nacl_b64_encode
{
  SCM_VALIDATE_BYTEVECTOR(1, buf);
  int variant = symbol_to_varaint (style);
  if (-1 == variant)
    return SCM_BOOL_F;

  size_t len = sodium_base64_ENCODED_LEN(SCM_BYTEVECTOR_LENGTH (buf), variant);

  char *b64enc = malloc (len);
  assert (b64enc);
  memset (b64enc, 0, len);


  b64enc = sodium_bin2base64(b64enc, len,
                             (uint8_t *)SCM_BYTEVECTOR_CONTENTS (buf),
                             SCM_BYTEVECTOR_LENGTH (buf),
                             variant);

  assert (b64enc);

  return scm_take_locale_string (b64enc);
}
#undef FUNC_NAME

SCM_DEFINE (scm_nacl_b64_decode, "nacl-decode-base64", 1, 1, 0,
            (SCM encoded, SCM style),
            "Returns a bytevector decoded from @var{style}")
#define FUNC_NAME s_scm_nacl_b64_decode
{

  SCM_VALIDATE_STRING(1,encoded);
  int variant = symbol_to_varaint (style);
  if (-1 == variant)
    return SCM_BOOL_F;

  static const char * ignore = " \r\n";

  size_t lenp;
  char *c_encoded = scm_to_locale_stringn (encoded, &lenp);
  if (!c_encoded)
    return SCM_BOOL_F;

  uint8_t *tmp = malloc (lenp);
  assert (tmp);
  memset(tmp, 0, lenp);

  size_t bin_len;

  int rc = sodium_base642bin(tmp, lenp,
                             c_encoded, lenp,
                             ignore, &bin_len,
                             NULL, variant);

  memset (c_encoded, 0, lenp);
  free (c_encoded);
  c_encoded = 0;

  SCM result;
  if (0 == rc)
    {
      result = scm_c_make_bytevector (bin_len);
      memcpy (SCM_BYTEVECTOR_CONTENTS(result), tmp, bin_len);
    }
  else
    {
      result = SCM_BOOL_F;
    }

  memset (tmp, 0, lenp);
  free (tmp);
  tmp = 0;

  return result;
}



#undef FUNC_NAME

SCM_DEFINE (scm_nacl_hash_sha256, "nacl-hash-sha256", 1, 0, 0,
            (SCM bv),
            "Returns a bytevector of the sha256 of @var{bv}")
#define FUNC_NAME s_scm_nacl_hash_sha256
{
  SCM_VALIDATE_BYTEVECTOR(1,bv);

  SCM out = scm_c_make_bytevector (crypto_hash_sha256_BYTES);
  if (0 != crypto_hash_sha256((uint8_t *)SCM_BYTEVECTOR_CONTENTS(out),
                              (uint8_t *)SCM_BYTEVECTOR_CONTENTS(bv),
                              SCM_BYTEVECTOR_LENGTH(bv)))
    {
      return SCM_BOOL_F;
    }

  return out;
}
#undef FUNC_NAME

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

int
set_interface_attribs (int fd, int speed, int parity)
{
  struct termios tty;
  memset (&tty, 0, sizeof tty);
  if (tcgetattr (fd, &tty) != 0)
    {
      printf ("error %d from tcgetattr", errno);
      return -1;
    }

  cfsetospeed (&tty, speed);
  cfsetispeed (&tty, speed);

  tty.c_cflag = (tty.c_cflag & ~CSIZE) | CS8;     // 8-bit chars
  // disable IGNBRK for mismatched speed tests; otherwise receive break
  // as \000 chars
  tty.c_iflag &= ~IGNBRK;         // disable break processing
  tty.c_lflag = 0;                // no signaling chars, no echo,
  // no canonical processing
  tty.c_oflag = 0;                // no remapping, no delays
  tty.c_cc[VMIN]  = 0;            // read doesn't block
  tty.c_cc[VTIME] = 5;            // 0.5 seconds read timeout

  tty.c_iflag &= ~(IXON | IXOFF | IXANY); // shut off xon/xoff ctrl

  tty.c_cflag |= (CLOCAL | CREAD);// ignore modem controls,
  // enable reading
  tty.c_cflag &= ~(PARENB | PARODD);      // shut off parity
  tty.c_cflag |= parity;
  tty.c_cflag &= ~CSTOPB;
  tty.c_cflag &= ~CRTSCTS;

  if (tcsetattr (fd, TCSANOW, &tty) != 0)
    {
      printf ("error %d from tcsetattr", errno);
      return -1;
    }
  return 0;
}

void
set_blocking (int fd, int should_block)
{
  struct termios tty;
  memset (&tty, 0, sizeof tty);
  if (tcgetattr (fd, &tty) != 0)
    {
      printf ("error %d from tggetattr", errno);
      return;
    }

  tty.c_cc[VMIN]  = should_block ? 1 : 0;
  tty.c_cc[VTIME] = 5;            // 0.5 seconds read timeout

  if (tcsetattr (fd, TCSANOW, &tty) != 0)
    printf ("error %d setting term attributes", errno);
}


#include <fcntl.h>
#include <sys/epoll.h>

SCM_DEFINE (scm_serial_terminal, "serial-term", 1, 0, 0,
            (SCM path),
            "Get the serial port")
#define FUNC_NAME s_scm_serial_terminal
{
  SCM_VALIDATE_STRING(1,path);


#define MAX_BUF     1000        /* Maximum bytes fetched by a single read() */
#define MAX_EVENTS     5        /* Maximum number of events to be returned from
                                   a single epoll_wait() call */
  int epfd, ready, fd, s, j;
  struct epoll_event ev;
  struct epoll_event evlist[MAX_EVENTS];
  char buf[MAX_BUF];

  epfd = epoll_create(1);
  assert (-1 != epfd);

  /* Open each file on command line, and add it to the "interest
     list" for the epoll instance */

  char *portname =  scm_to_locale_string (path);
  fd = open (portname, O_RDONLY | O_NOCTTY | O_SYNC);

  if (fd == -1)
    {
      free (portname);
      return SCM_BOOL_F;
    }

  printf("Opened on fd %d\n",  fd);
  set_interface_attribs (fd, B115200, 0);  // set speed to 115,200 bps, 8n1 (no parity)
  set_blocking (fd, 0);                // set no blocking

  ev.events = EPOLLIN;            /* Only interested in input events */
  ev.data.fd = fd;
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) == -1)
    {
      printf ("error epoll_ctl\n");
      return SCM_BOOL_F;
    }


  while (1)
    {
      ready = epoll_wait(epfd, evlist, MAX_EVENTS, -1);
      if (ready == -1)
        {
          if (errno == EINTR)
            return SCM_BOOL_F;
          else
            {
              printf ("epoll_wait\n");
              return SCM_BOOL_F;
            }
        }

      /* Deal with returned list of events */

      for (j = 0; j < ready; j++)
        {

          if (evlist[j].events & EPOLLERR)
            {
              printf("    closing fd %d\n", evlist[j].data.fd);
              if (close(evlist[j].data.fd) == -1)
                {
                  printf("close\n");
                  return SCM_BOOL_F;
                }
              return SCM_BOOL_T;
            }
          if (evlist[j].events & EPOLLIN)
            {
              memset(buf, 0, MAX_BUF);
              s = read(evlist[j].data.fd, buf, MAX_BUF);
              if (s == -1)
                {
                  printf ("read\n");
                  return SCM_BOOL_F;
                }
              printf ("%.*s", s, buf);

            }
        }

    }



}
#undef FUNC_NAME

void
scm_init_nacl (void)
{
  static int initialized = 0;

  if (initialized)
    return;

  int rc = sodium_init();
  assert (-1 != rc);

#ifndef SCM_MAGIC_SNARFER
#include "guile-nacl.x"
#endif


  initialized = 1;
}
