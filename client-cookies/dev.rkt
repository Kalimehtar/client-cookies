#lang racket/base

(require racket/list racket/string racket/date
         net/head net/url)

(provide (struct-out cookie)
         parse-date
         domain-match? path-match?
         save-cookies!
         set-save-cookie! set-headers+cookies 
         headers+cookies
         cookie-jar)

;;; Based on RFC 6265

;; section 5.3
(struct cookie (name value 
                     expiry-time domain path creation-time
                     [last-access-time #:mutable]
                     persistent-flag host-only-flag secure-only-flag http-only-flag))

;; section 5.1.1
(define (parse-date str)
  (define (range+ a b) (cons b (range a b)))
  (define delimiter  `(#x09 ,@(range+ #x20 #x2F) 
                            ,@(range+ #x3B #x40) 
                            ,@(range+ #x5B #x60) 
                            ,@(range+ #x7B #x7E)))
  (define month-names  `("jan" "feb" "mar" "apr" "may" "jun" 
                               "jul" "aug" "sep" "oct" "nov" "dec"))
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
  (cond 
    [time
     (define-values (hour minute second) (apply values time))
     (and day month year (date second minute hour day month year 0 0 #f 0))]
    [else #f]))

;; section 5.1.3

(define (domain-match? domain host)
  (define diff (- (string-length host) (string-length domain)))
  (and (diff . >= . 0)
       (string=? domain (substring host diff))
       (or (= diff 0) (char=? (string-ref host (sub1 diff)) #\.))
       (not (regexp-match #px"\\.\\d\\d?\\d?$" host))))

;; section 5.1.4

(define (path-match? cookie-path url)
  (cond
    [(url? url) (path-match? cookie-path (url-full-path url))]
    [else
     (define len-cookie (string-length cookie-path))
     (define len-uri (string-length url))
     (and (<= len-cookie len-uri)
          (string=? (substring url 0 len-cookie) cookie-path)
          (or (char=? (string-ref cookie-path (sub1 len-cookie)) #\/)
              (and (< len-cookie len-uri) (char=? (string-ref url len-cookie) #\/))))]))

(define (url-full-path url)
  (cond
    [(url? url)
     (string-append "/" 
                    (string-join (map path/param-path (url-path url)) "/"))]
    [else (url-full-path (string->url url))]))

(define (save-cookies! url headers)
  (define current-time (current-seconds))  
  (define (name-value str sep)
    (define pos (for/or ([ch (in-string str)]
                         [i (in-naturals)])
                  (if (char=? ch sep) i #f)))
    (if pos
        (values (string-trim (substring str 0 pos))
                (string-trim (substring str (add1 pos))))
        (values (string-trim str) "")))
  (define (parse-cookie-header x)
    (cond 
      [(string? x) 
       (define-values (name value) (name-value x #\:))
       (parse-cookie-header (cons name value))]
      [(and (cons? x) (string=? (string-downcase (car x)) "set-cookie")) (cdr x)]
      [else #f]))
  (define (parse-cookie str url)
    (cond 
      [(string? str)
       (define host (url-host url))
       (define (default-path)
         (define path (url-full-path url))
         (cond
           [(= (string-length path) 0) "/"]
           [(not (char=? (string-ref path 0) #\/)) "/"]
           [else
            (define last 
              (for/last ([c (in-string path)]
                         [i (in-naturals)]                         
                         #:when (char=? c #\/))
                i))
            (if (= last 0)
                "/"
                (substring path 0 last))]))
       (define l (string-split str ";"))
       (define-values (name value) (name-value (car l) #\=))
       (define-values (expires max-age domain path secure http-only)
         (for/fold ([expires #f] [max-age #f] [domain #f] [path #f] [secure #f] [http-only #f])
           ([cookie-av (in-list (cdr l))])
           (define-values (name value) (name-value cookie-av #\=))
           (define iname (string-downcase name))
           (cond
             [(string=? iname "expires") (values (parse-date value) max-age domain path secure http-only)]
             [(string=? iname "max-age") (values expires 
                                                 (if (regexp-match #px"-?\\d+" value) (string->number value) max-age) 
                                                 domain path secure http-only)]
             [(and (string=? iname "domain") (not (string=? value host))) 
              (values expires max-age (string-downcase value) path secure http-only)]
             [(and (string=? iname "path") (> (string-length value) 0) (char=? (string-ref value 0) #\\))
              (values expires max-age domain value secure http-only)]
             [(string=? iname "secure") (values expires max-age domain path #t http-only)]
             [(string=? iname "http-only") (values expires max-age domain path secure #t)]
             [else (values expires max-age domain path secure http-only)])))
       (cond 
         [(or (not domain) (domain-match? domain host))
          (define expires-seconds
            (cond
              [max-age (+ max-age current-time)]
              [expires => date->seconds]
              [else (+ current-time 10000000)]))
          (define (bool x) (if x #t #f))
          (cookie name value expires-seconds
                  (or domain host)
                  (or path (default-path)) current-time current-time
                  (bool (or max-age expires)) (bool domain)
                  http-only secure)]
         [else #f])]
      [else #f]))
  (cond
    [(string? headers) (save-cookies! url (extract-all-fields headers))]
    [(string? url) (save-cookies! (string->url url) headers)]
    [else
     (for* ([header (in-list headers)]
            [cookie (in-value (parse-cookie (parse-cookie-header header) url))]
            #:when cookie)
       (save-cookie! cookie))]))


(define cookie-jar '())

(define (cookie-ok? cookie [current-time (current-seconds)])
  (>= (cookie-expiry-time cookie) current-time))

(define (default-save-cookie! a-cookie)
  (define-values (name domain path creation-time)
    (apply values (for/list ([f (in-list (list cookie-name cookie-domain cookie-path cookie-creation-time))])
                    (f a-cookie))))
  (define len (string-length path))
  (define current-time (current-seconds))
  (set! cookie-jar 
        (let loop ([acc '()] [jar cookie-jar])          
          (define (with-new [a-cookie a-cookie])
            (if (cookie-ok? a-cookie) (cons a-cookie acc) acc))
          (cond
            [(null? jar) (reverse (with-new))]
            [else
             (define head (car jar))
             (cond               
               [(let ([len-head (string-length (cookie-path head))])
                  (or (< len len-head)
                      (and (= len len-head) (> creation-time (cookie-creation-time head)))))
                (append (reverse (with-new)) jar)]
               [(and (string=? name (cookie-name head))
                     (string=? path (cookie-path head))
                     (string=? domain (cookie-domain head)))
                (append (reverse (with-new (struct-copy cookie a-cookie 
                                                        [creation-time (cookie-creation-time head)]))) 
                        (cdr jar))]
               [(cookie-ok? head) (loop (cons head acc) (cdr jar))]
               [else (loop acc (cdr jar))])]))))

(define (default-headers+cookies url headers)
  (cond
    [(string? url) (default-headers+cookies (string->url url) headers)]
    [else
     (define host (url-host url))
     (define (match? cookie)
       (and (domain-match? (cookie-domain cookie) host)
            (path-match? (cookie-path cookie) url)))
     (define filtered (for/list ([cookie (in-list cookie-jar)]
                                 #:when (match? cookie))
                        (format "~a=~a" (cookie-name cookie) (cookie-value cookie))))
     (if (null? filtered)
         headers
         (cons (string-append "Cookies: " (string-join filtered ";")) headers))]))

(define (set-save-cookie! new) (set! save-cookie! new))
(define (set-headers+cookies new) (set! headers+cookies new))
(define save-cookie! default-save-cookie!)
(define headers+cookies default-headers+cookies)
