;;; wyrm.el --- Wyrm LSP for OTM threat models (Eglot)  -*- lexical-binding: t; -*-
;;
;; Requires wyrm-lsp on PATH:
;;   cargo install --git https://github.com/1ARdotNO/wyrm wyrm-lsp
;;
;; Add this to your init.el.

;; A derived mode scoped to *.otm.yaml so the server only attaches to threat
;; models (inherits YAML highlighting). Uses yaml-ts-mode if available.
(defvar wyrm-otm-parent-mode
  (if (fboundp 'yaml-ts-mode) 'yaml-ts-mode 'yaml-mode)
  "Base major mode for OTM files.")

(define-derived-mode wyrm-otm-mode
  ;; `define-derived-mode' needs a literal parent; fall back to prog-mode and
  ;; re-parent below if yaml modes load lazily.
  prog-mode "OTM"
  "Major mode for wyrm OTM threat models.")

(add-to-list 'auto-mode-alist '("\\.otm\\.ya?ml\\'" . wyrm-otm-mode))

(with-eval-after-load 'eglot
  (add-to-list 'eglot-server-programs '(wyrm-otm-mode . ("wyrm-lsp"))))

(add-hook 'wyrm-otm-mode-hook #'eglot-ensure)

;; lsp-mode alternative:
;;   (with-eval-after-load 'lsp-mode
;;     (add-to-list 'lsp-language-id-configuration '(wyrm-otm-mode . "yaml"))
;;     (lsp-register-client
;;      (make-lsp-client :new-connection (lsp-stdio-connection "wyrm-lsp")
;;                       :activation-fn (lsp-activate-on "yaml")
;;                       :server-id 'wyrm)))

(provide 'wyrm)
;;; wyrm.el ends here
