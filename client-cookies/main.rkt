#lang racket/base
(require "dev.rkt" net/url)
(provide save-cookies! headers+cookies get-pure-port/cookies get-pure-port/headers/cookies)

(define (get-pure-port/headers/cookies url headers #:redirections [redirections 0] #:status? [status #f])
  (define-values (port reply-headers) 
    (get-pure-port/headers url (headers+cookies url headers) #:redirections redirections #:status status))
  (save-cookies! reply-headers)
  (values port reply-headers))

(define (get-pure-port/cookies url headers #:redirections [redirections 0])
  (call-with-values (get-pure-port/headers/cookies url headers #:redirections redirections)
                    (λ (port _) port)))
    
  
