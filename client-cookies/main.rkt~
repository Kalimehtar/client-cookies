#lang racket
(require net/head net/url)

;;; Based on RFC 6265

;; section 5.3
(struct cookie (name
   value expiry-time domain path creation-time last-access-time
   persistent-flag host-only-flag secure-only-flag http-only-flag))

;; section 5.1.1
(define (parse-date str)
  (define delimiter  `(#x09 ,@(range #x20 #x2F) #x2F 
                            ,@(range #x3B #x40) #x40 
                            ,@(range #x5B #x60) #x60 
                            ,@(range #x7B #x7E) #x7E))
  (define month-names  `("jan" "feb" "mar" "apr" "may" "jun" "jul" "aug"
                               "sep" "oct" "nov" "dec"))
  (define tokens 
    (let-values ([(acc current)
                  (for/fold ([acc null] [current null])
                            ([ch (in-string str)])
                    (if (memv (char->integer ch) delimiter)
                        (values (cons (list->string (reverse current)) acc) null)
                        (values acc (cons ch current))))])
      (reverse (if (null? current) acc (cons current acc)))))
  (define (parse-time str)
    (cond
      [(regexp-match #px"^(\\d\\d?):(\\d\\d?):(\\d\\d?)\\D*$" str) => (λ (x) (map string->number (cdr x)))]
      [else #f]))
  (define (parse-day str)
    (cond
      [(regexp-match #px"^(\\d\\d?)\\D*$" str) => (λ (x) (string->number (cadr x)))]
      [else #f]))
  (define (parse-year str)
    (cond
      [(regexp-match #px"^(\\d\\d\\d?\\d?)\\D*$" str) => (λ (x) (string->number (cadr x)))]
      [else #f]))
  (define (parse-month str)
    (cond
      [(>= (string-length str) 3)
       (define prefix (string-downcase (substring str 0 3)))
       (for/or ([m (in-list month-names)]
                [n (in-naturals)])
         (if (string=? m prefix) (add1 n) #f))]
      [else #f]))
  (define-values (time day month year)
    (for/fold ([time #f] [day #f] [month #f] [year #f])
              ([token (in-list tokens)])
      (cond
        [(and (not time) (parse-time token)) => (λ (time) (values time day month year))]
        [(and (not day) (parse-day token)) => (λ (day) (values time day month year))]
        [(and (not month) (parse-month token)) => (λ (month) (values time day month year))]
        [(and (not year) (parse-year token)) => (λ (year) (values time day month year))]
        [else (values time day month year)])))
  (when time
    (define-values (hour minute second) (apply values time))
    (and day month year (date second minute hour day month year 0 0 #f 0))))

;; section 5.1.3

(define (domain-match domain host)
  (define diff (- (string-length host) (string-length domain)))
  (and (diff . >= . 0)
       (string=? domain (substring host diff))
       (or (= diff 0) (char=? (string-ref host (sub1 diff)) #\.))
       (not (regexp-match #px"\\.\\d\\d?\\d?$" host))))

(define (save-cookies! uri headers)
  (define (name-value str sep)
    (define pos (for/or ([ch (in-string str)]
                         [i (in-naturals)])
                  (if (char=? ch sep) i #f)))
    (values (string-trim (substring str 0 pos))
            (string-trim (substring str (add1 pos)))))
  (define (parse-cookie-header x)
    (cond 
      [(string? x) 
       (define-values (name value) (name-value x #\:))
       (parse-cookie-header (cons name value))]
      [(string=? (string-downcase (car x) "set-cookie") (cdr x))]
      [else #f]))
  (define (parse-cookie str url)
    (define (good-domain domain)
      #t)
    (define (default-path url)
      (string-append 
       "/" (string-join (map path/param-path (url-path (string->url url))) "/")))
    (define l (string-split str ";"))
    (define-values (name value) (name-value (car l) #\=))
    (define-values (expires max-age domain path secure http-only)
      (for/fold ([expires #f] [max-age #f] [domain ""] [path #f] [secure #f] [http-only #f])
                ([cookie-av (in-list (cdr l))])
        (define-values (name value) (name-value cookie-av #\=))
        (define iname (string-downcase name))
        (cond
          [(string=? iname "expires") (values (parse-date value) max-age domain path secure http-only)]
          [(string=? iname "max-age") (values expires (string->number value) domain path secure http-only)]
          [(string=? iname "domain") (values expires max-age (string-downcase value) path secure http-only)]
          [(and (string=? iname "path") (> (string-length value) 0) (char=? (string-ref value 0) #\\))
           (values expires max-age domain value secure http-only)]
          [(string=? iname "secure") (values expires max-age domain path #t http-only)]
          [(string=? iname "http-only") (values expires max-age domain path secure #t)])))
    (values (if (good-domain domain) name #f) value 
            (or expires (seconds->date (+ max-age (current-seconds))))
            domain 
            (or path (default-path))
            secure http-only))
  (cond
    [(string? headers) (save-cookies! url (extract-all-fields headers))]
    [(string? url) (save-cookies! (string->url url) headers)]
    [else 
     (for* ([header (in-list headers)]
            [parsed (in-value (parse-cookie-header header))]
            #:when parsed)
       (define-values (name value expires max-age domain path secure http-only) (parse-cookie parsed url))
       (when name
         ((save-cookie!) name value expires domain path secure http-only)))]))

(define save-cookie! (make-parameter default-save-cookie!))
(define add-cookies (make-parameter default-add-cookies))

(define cookie-jar (make-hash))
(define (default-save-cookie! name value expires domain path secure http-only)
  (define key (list name domain path))
  (hash-set! cookie-jar key (list value expires secure http-only)))

(define (default-add-cookies url headers)
  (for/list ([(k v) (in-hash cookie-jar)])
    (define-values (name domain path) (apply values k))
    (define-values (expires secure http-only) (apply values k))
    1))

(struct a (x y))