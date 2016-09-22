;; guile-zmq
;; Copyright (C) 2011,2012 Andy Wingo <wingo at pobox dot com>

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU Lesser General Public License as
;; published by the Free Software Foundation; either version 3 of the
;; License, or (at your option) any later version.
;;
;; This program is distributed in the hope that it will be useful, but
;; WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
;; Lesser General Public License for more details.
;;
;; You should have received a copy of the GNU Lesser General Public
;; License along with this program; if not, contact:
;;
;; Free Software Foundation, Inc.     Voice:  +1-617-542-5942
;; 51 Franklin Street, Fifth Floor    Fax:    +1-617-542-2652
;; Boston, MA  02110-1301,  USA       gnu@gnu.org

;;; Commentary:
;;
;; This is the libsodium wrapper for Guile.
;;
;; See the libsodium documentation for more details.
;;
;;; Code:

(define-module (nacl)
  #:use-module (nacl config)
  #:use-module (rnrs bytevectors)
  #:export (nacl-version

            nacl-init
            nacl-rand-buf))

;; This will export many things
(dynamic-call "scm_init_nacl" (dynamic-link *nacl-lib-path*))


#;
(if (not (member *zmq-documentation-path* documentation-files))
    (set! documentation-files (cons *zmq-documentation-path*
                                    documentation-files)))
