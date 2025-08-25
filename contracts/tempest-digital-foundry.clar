;; TempestDigitalFoundry - Storm-powered digital creation workshop
;; A revolutionary decentralized platform for creative asset management and collaborative curation
;; Built with Clarity for maximum security, transparency, and immutable record keeping
;; Enables seamless rights management, community-driven galleries, and thematic collections



;; Global State Variables for Quantum Creative Hub Operations
(define-data-var quantum-artifact-sequence uint u0)   ;; Sequential counter for registered creative artifacts
(define-data-var thematic-collection-sequence uint u0)      ;; Sequential counter for curated thematic collections

;; System Error Constants for Robust Error Handling
(define-constant ERR-UNAUTHORIZED-OPERATION (err u306)) 
(define-constant ERR-ADMIN-REQUIRED (err u307))
(define-constant ERR-DUPLICATE-ENTRY (err u302)) 
(define-constant ERR-INVALID-PARAMETERS (err u303)) 
(define-constant ERR-OPERATION-FORBIDDEN (err u308))  
(define-constant QUANTUM-HUB-ADMIN tx-sender)  
(define-constant ERR-ENTITY-NOT-EXISTS (err u301))
(define-constant ERR-BOUNDARY-VIOLATION (err u304)) 
(define-constant ERR-AUTHENTICATION-FAILED (err u305))

;; Creative Artifact Registry with Comprehensive Metadata
(define-map creative-artifact-registry
    {artifact-sequence: uint}  ;; Unique sequential identifier for each creative piece
    {
        creative-title: (string-ascii 64),           ;; Display name of the creative work
        artist-identity: (string-ascii 32),          ;; Creator's recognized identity
        rights-holder: principal,                    ;; Current legal owner with full rights
        temporal-duration: uint,                     ;; Length in seconds for time-based media
        genesis-block: uint,                         ;; Block height at registration time
        creative-category: (string-ascii 32),        ;; Genre or category classification
        descriptor-labels: (list 8 (string-ascii 24))    ;; Searchable metadata tags
    }
)

;; Access Control Matrix for Creative Artifacts
(define-map quantum-access-control
    {artifact-sequence: uint, authorized-entity: principal}  ;; Artifact ID and authorized user
    {permission-granted: bool}  ;; Boolean flag for access authorization
)

;; Personal Curation Collections Management
(define-map personal-curation-spaces
    {collection-curator: principal, space-identifier: uint}  ;; Curator and collection ID
    {
        collection-label: (string-ascii 64),            ;; Human-readable collection name
        collection-summary: (string-ascii 128),         ;; Brief description of collection purpose
        initialization-block: uint,                     ;; Block height when collection was created
        last-modification-block: uint,                   ;; Most recent update timestamp
        contained-artifacts: uint,                       ;; Running count of included artifacts
        public-visibility: bool                          ;; Whether collection is publicly browsable
    }
)

;; Artifact Placement within Personal Collections
(define-map curation-space-contents
    {collection-curator: principal, space-identifier: uint, artifact-sequence: uint}  ;; Curator, collection, and artifact
    {
        placement-timestamp: uint,     ;; When artifact was added to collection
        presentation-order: uint       ;; Sequential position for display ordering
    }
)

;; Curator Collection Counter Management
(define-map curator-sequence-tracker
    {collection-curator: principal}  ;; Individual curator principal
    {current-max-sequence: uint}  ;; Highest collection ID number for this curator
)

;; Permission Grant Historical Records
(define-map access-grant-ledger
    {artifact-sequence: uint, permission-grantor: principal, permission-recipient: principal}  ;; Complete grant context
    {
        authorization-block: uint,     ;; Block height when permission was granted
        revocation-block: uint,        ;; Block height when revoked, zero if still active
        currently-active: bool         ;; Quick lookup for active status
    }
)

;; Community Assessment and Rating System
(define-map community-artifact-assessments
    {artifact-sequence: uint, community-assessor: principal}  ;; Artifact and reviewer pair
    {
        numerical-rating: uint,                          ;; Star rating from 1 to 5
        textual-commentary: (optional (string-ascii 256)),  ;; Optional written feedback
        assessment-timestamp: uint,                      ;; Most recent review update
        initial-assessment-block: uint                   ;; First time this user reviewed
    }
)

;; Aggregate Assessment Metrics Tracking
(define-map artifact-assessment-metrics
    {artifact-sequence: uint}  ;; Target artifact identifier
    {
        community-assessment-count: uint,         ;; Total number of community reviews received
        most-recent-assessment-block: uint        ;; Block height of the latest review
    }
)

;; Thematic Showcase Collection Registry
(define-map thematic-showcase-registry
    {collection-sequence: uint}  ;; Sequential showcase identifier
    {
        showcase-title: (string-ascii 64),           ;; Public display name for the showcase
        showcase-description: (string-ascii 256),    ;; Detailed narrative explaining the showcase
        showcase-originator: principal,              ;; Principal who initiated this showcase
        thematic-focus: (string-ascii 32),           ;; Central theme or concept
        creation-block: uint,                        ;; Block height at showcase creation
        modification-block: uint,                    ;; Last update or change timestamp
        included-artifacts: uint,                    ;; Count of artifacts currently featured
        community-contributions-enabled: bool       ;; Whether others can contribute artifacts
    }
)

;; Showcase Participation Registry
(define-map showcase-participation-registry
    {collection-sequence: uint, participant-entity: principal}  ;; Showcase and participant pair
    {
        participation-status: bool,         ;; Whether participant is currently active
        participation-start_block: uint,    ;; When participant joined the showcase
        originator-privilege: bool          ;; Whether this participant created the showcase
    }
)

;; Artifact Integration into Thematic Showcases
(define-map showcase-artifact-integration
    {collection-sequence: uint, artifact-sequence: uint}  ;; Showcase and artifact identifiers
    {
        contributing-participant: principal,      ;; Who contributed this specific artifact
        integration-timestamp: uint              ;; Block height when artifact was added
    }
)

;; Utility Validation Functions for Internal Operations

;; Validates that a creative artifact exists in the registry
(define-private (validate-artifact-existence (artifact-sequence uint))
    (is-some (map-get? creative-artifact-registry {artifact-sequence: artifact-sequence}))
)

;; Confirms ownership rights for a specific artifact
(define-private (confirm-artifact-ownership (artifact-sequence uint) (potential-owner principal))
    (match (map-get? creative-artifact-registry {artifact-sequence: artifact-sequence})
        artifact-record (is-eq (get rights-holder artifact-record) potential-owner)
        false
    )
)

;; Extracts temporal duration from artifact record
(define-private (extract-artifact-duration (artifact-sequence uint))
    (default-to u0 
        (get temporal-duration 
            (map-get? creative-artifact-registry {artifact-sequence: artifact-sequence})
        )
    )
)

;; Validates individual descriptor label format
(define-private (validate-descriptor-format (descriptor-label (string-ascii 24)))
    (and 
        (> (len descriptor-label) u0)
        (< (len descriptor-label) u25)
    )
)

;; Validates complete descriptor label collection
(define-private (validate-descriptor-collection (descriptor-labels (list 8 (string-ascii 24))))
    (and
        (> (len descriptor-labels) u0)
        (<= (len descriptor-labels) u8)
        (is-eq (len (filter validate-descriptor-format descriptor-labels)) (len descriptor-labels))
    )
)

;; Retrieves highest collection sequence for a curator
(define-private (get-curator-max-sequence (collection-curator principal))
    (get current-max-sequence (default-to {current-max-sequence: u0} 
        (map-get? curator-sequence-tracker {collection-curator: collection-curator})))
)

;; Transforms artifact ID for batch processing operations
(define-private (transform-artifact-for-batch (artifact-sequence uint))
    {artifact-sequence: artifact-sequence}
)

;; Integrates artifact into showcase during batch operations
(define-private (integrate-artifact-to-showcase (artifact-data {artifact-sequence: uint}))
    (let
        ((target-artifact (get artifact-sequence artifact-data)))
        (and 
            (validate-artifact-existence target-artifact)
            (map-insert showcase-artifact-integration
                {collection-sequence: (var-get thematic-collection-sequence), artifact-sequence: target-artifact}
                {
                    contributing-participant: tx-sender,
                    integration-timestamp: block-height
                }
            )
        )
    )
)

;; Primary Public Interface Functions

;; Registers new creative artifacts in the quantum hub
(define-public (register-creative-artifact 
        (creative-title (string-ascii 64))
        (artist-identity (string-ascii 32))
        (temporal-duration uint)
        (creative-category (string-ascii 32))
        (descriptor-labels (list 8 (string-ascii 24)))
    )
    (let
        ((next-artifact-sequence (+ (var-get quantum-artifact-sequence) u1)))

        ;; Comprehensive parameter validation before registration
        (asserts! (and (> (len creative-title) u0) (< (len creative-title) u65)) ERR-INVALID-PARAMETERS)
        (asserts! (and (> (len artist-identity) u0) (< (len artist-identity) u33)) ERR-INVALID-PARAMETERS)
        (asserts! (and (> temporal-duration u0) (< temporal-duration u10000)) ERR-BOUNDARY-VIOLATION)
        (asserts! (and (> (len creative-category) u0) (< (len creative-category) u33)) ERR-INVALID-PARAMETERS)
        (asserts! (validate-descriptor-collection descriptor-labels) ERR-INVALID-PARAMETERS)

        ;; Create new artifact registry entry
        (map-insert creative-artifact-registry
            {artifact-sequence: next-artifact-sequence}
            {
                creative-title: creative-title,
                artist-identity: artist-identity,
                rights-holder: tx-sender,
                temporal-duration: temporal-duration,
                genesis-block: block-height,
                creative-category: creative-category,
                descriptor-labels: descriptor-labels
            }
        )

        ;; Grant automatic access to the rights holder
        (map-insert quantum-access-control
            {artifact-sequence: next-artifact-sequence, authorized-entity: tx-sender}
            {permission-granted: true}
        )

        ;; Update sequence counter and return new artifact identifier
        (var-set quantum-artifact-sequence next-artifact-sequence)
        (ok next-artifact-sequence)
    )
)

;; Facilitates ownership transfer between principals
(define-public (transfer-ownership-rights (artifact-sequence uint) (new-rights-holder principal))
    (let
        ((current-artifact-data (unwrap! (map-get? creative-artifact-registry {artifact-sequence: artifact-sequence}) ERR-ENTITY-NOT-EXISTS)))

        ;; Validate artifact existence and current ownership
        (asserts! (validate-artifact-existence artifact-sequence) ERR-ENTITY-NOT-EXISTS)
        (asserts! (is-eq (get rights-holder current-artifact-data) tx-sender) ERR-AUTHENTICATION-FAILED)

        ;; Execute ownership transfer by updating registry
        (map-set creative-artifact-registry
            {artifact-sequence: artifact-sequence}
            (merge current-artifact-data {rights-holder: new-rights-holder})
        )
        (ok true)
    )
)

;; Updates metadata for existing creative artifacts
(define-public (modify-artifact-metadata 
        (artifact-sequence uint) 
        (updated-title (string-ascii 64)) 
        (updated-duration uint) 
        (updated-category (string-ascii 32)) 
        (updated-descriptors (list 8 (string-ascii 24)))
    )
    (let
        ((current-artifact-data (unwrap! (map-get? creative-artifact-registry {artifact-sequence: artifact-sequence}) ERR-ENTITY-NOT-EXISTS)))

        ;; Validate ownership and parameters before modification
        (asserts! (validate-artifact-existence artifact-sequence) ERR-ENTITY-NOT-EXISTS)
        (asserts! (is-eq (get rights-holder current-artifact-data) tx-sender) ERR-AUTHENTICATION-FAILED)
        (asserts! (and (> (len updated-title) u0) (< (len updated-title) u65)) ERR-INVALID-PARAMETERS)
        (asserts! (and (> updated-duration u0) (< updated-duration u10000)) ERR-BOUNDARY-VIOLATION)
        (asserts! (and (> (len updated-category) u0) (< (len updated-category) u33)) ERR-INVALID-PARAMETERS)
        (asserts! (validate-descriptor-collection updated-descriptors) ERR-INVALID-PARAMETERS)

        ;; Apply metadata updates to the registry
        (map-set creative-artifact-registry
            {artifact-sequence: artifact-sequence}
            (merge current-artifact-data {
                creative-title: updated-title,
                temporal-duration: updated-duration,
                creative-category: updated-category,
                descriptor-labels: updated-descriptors
            })
        )
        (ok true)
    )
)

;; Integrates artifacts into personal curation collections
(define-public (integrate-into-curation-space 
        (space-identifier uint)
        (artifact-sequence uint)
    )
    (let
        ((target-collection (unwrap! (map-get? personal-curation-spaces {collection-curator: tx-sender, space-identifier: space-identifier}) ERR-ENTITY-NOT-EXISTS))
         (target-artifact (unwrap! (map-get? creative-artifact-registry {artifact-sequence: artifact-sequence}) ERR-ENTITY-NOT-EXISTS))
         (user-access-rights (default-to {permission-granted: false} (map-get? quantum-access-control {artifact-sequence: artifact-sequence, authorized-entity: tx-sender}))))

        ;; Validate artifact existence and user permissions
        (asserts! (validate-artifact-existence artifact-sequence) ERR-ENTITY-NOT-EXISTS)
        (asserts! (or 
                    (is-eq (get rights-holder target-artifact) tx-sender)
                    (get permission-granted user-access-rights)
                  ) 
                ERR-UNAUTHORIZED-OPERATION)

        ;; Prevent duplicate entries in the same collection
        (asserts! (is-none (map-get? curation-space-contents {collection-curator: tx-sender, space-identifier: space-identifier, artifact-sequence: artifact-sequence})) 
                 ERR-DUPLICATE-ENTRY)

        (ok true)
    )
)

;; Establishes access permissions for creative artifacts
(define-public (establish-artifact-access 
        (artifact-sequence uint)
        (access-recipient principal)
    )
    (let
        ((target-artifact (unwrap! (map-get? creative-artifact-registry {artifact-sequence: artifact-sequence}) ERR-ENTITY-NOT-EXISTS)))

        ;; Validate artifact existence and ownership for permission granting
        (asserts! (validate-artifact-existence artifact-sequence) ERR-ENTITY-NOT-EXISTS)
        (asserts! (is-eq (get rights-holder target-artifact) tx-sender) ERR-AUTHENTICATION-FAILED)
        (asserts! (not (is-eq tx-sender access-recipient)) ERR-INVALID-PARAMETERS)

        ;; Prevent duplicate permission grants
        (asserts! (is-none (map-get? quantum-access-control {artifact-sequence: artifact-sequence, authorized-entity: access-recipient})) 
                 ERR-DUPLICATE-ENTRY)

        ;; Grant access permission
        (map-insert quantum-access-control
            {artifact-sequence: artifact-sequence, authorized-entity: access-recipient}
            {permission-granted: true}
        )

        ;; Record permission grant in historical ledger
        (map-insert access-grant-ledger
            {artifact-sequence: artifact-sequence, permission-grantor: tx-sender, permission-recipient: access-recipient}
            {
                authorization-block: block-height,
                revocation-block: u0,
                currently-active: true
            }
        )

        (ok true)
    )
)

;; Revokes previously granted access permissions
(define-public (revoke-artifact-access 
        (artifact-sequence uint)
        (access-recipient principal)
    )
    (let
        ((target-artifact (unwrap! (map-get? creative-artifact-registry {artifact-sequence: artifact-sequence}) ERR-ENTITY-NOT-EXISTS))
         (grant-record (unwrap! (map-get? access-grant-ledger {artifact-sequence: artifact-sequence, permission-grantor: tx-sender, permission-recipient: access-recipient}) ERR-ENTITY-NOT-EXISTS)))

        ;; Validate ownership and active grant status
        (asserts! (validate-artifact-existence artifact-sequence) ERR-ENTITY-NOT-EXISTS)
        (asserts! (is-eq (get rights-holder target-artifact) tx-sender) ERR-AUTHENTICATION-FAILED)
        (asserts! (get currently-active grant-record) ERR-UNAUTHORIZED-OPERATION)

        (ok true)
    )
)

;; Processes community assessments for creative artifacts
(define-public (process-community-assessment 
        (artifact-sequence uint)
        (numerical-rating uint)
        (textual-commentary (optional (string-ascii 256)))
    )
    (let
        ((target-artifact (unwrap! (map-get? creative-artifact-registry {artifact-sequence: artifact-sequence}) ERR-ENTITY-NOT-EXISTS))
         (user-access-rights (default-to {permission-granted: false} (map-get? quantum-access-control {artifact-sequence: artifact-sequence, authorized-entity: tx-sender})))
         (previous-assessment (map-get? community-artifact-assessments {artifact-sequence: artifact-sequence, community-assessor: tx-sender})))

        ;; Validate access rights and assessment parameters
        (asserts! (validate-artifact-existence artifact-sequence) ERR-ENTITY-NOT-EXISTS)
        (asserts! (or 
                    (is-eq (get rights-holder target-artifact) tx-sender)
                    (get permission-granted user-access-rights)
                  ) 
                ERR-UNAUTHORIZED-OPERATION)
        (asserts! (and (>= numerical-rating u1) (<= numerical-rating u5)) ERR-INVALID-PARAMETERS)

        ;; Validate optional commentary length
        (if (is-some textual-commentary)
            (asserts! (and 
                        (> (len (default-to "" textual-commentary)) u0) 
                        (< (len (default-to "" textual-commentary)) u257)
                      ) 
                    ERR-INVALID-PARAMETERS)
            true
        )

        ;; Process assessment (update existing or create new)
        (if (is-some previous-assessment)
            ;; Update existing community assessment
            (map-set community-artifact-assessments
                {artifact-sequence: artifact-sequence, community-assessor: tx-sender}
                {
                    numerical-rating: numerical-rating,
                    textual-commentary: textual-commentary,
                    assessment-timestamp: block-height,
                    initial-assessment-block: (get initial-assessment-block (unwrap! previous-assessment ERR-ENTITY-NOT-EXISTS))
                }
            )
            ;; Create new community assessment entry
            (map-insert community-artifact-assessments
                {artifact-sequence: artifact-sequence, community-assessor: tx-sender}
                {
                    numerical-rating: numerical-rating,
                    textual-commentary: textual-commentary,
                    assessment-timestamp: block-height,
                    initial-assessment-block: block-height
                }
            )
        )

        ;; Update aggregate assessment metrics
        (match (map-get? artifact-assessment-metrics {artifact-sequence: artifact-sequence})
            current-metrics (map-set artifact-assessment-metrics
                {artifact-sequence: artifact-sequence}
                (merge current-metrics {
                    community-assessment-count: (if (is-some previous-assessment) 
                                      (get community-assessment-count current-metrics) 
                                      (+ (get community-assessment-count current-metrics) u1)),
                    most-recent-assessment-block: block-height
                })
            )
            (map-insert artifact-assessment-metrics
                {artifact-sequence: artifact-sequence}
                {
                    community-assessment-count: u1,
                    most-recent-assessment-block: block-height
                }
            )
        )

        (ok true)
    )
)

;; Establishes thematic showcases for curated collections
(define-public (establish-thematic-showcase
        (showcase-title (string-ascii 64))
        (showcase-description (string-ascii 256))
        (thematic-focus (string-ascii 32))
        (founding-artifacts (list 20 uint))
        (community-contributions-enabled bool)
    )
    (let
        ((next-collection-sequence (+ (var-get thematic-collection-sequence) u1))
         (validated-artifacts (filter validate-artifact-existence founding-artifacts)))

        ;; Validate showcase parameters before creation
        (asserts! (and (> (len showcase-title) u0) (< (len showcase-title) u65)) ERR-INVALID-PARAMETERS)
        (asserts! (and (> (len showcase-description) u0) (< (len showcase-description) u257)) ERR-INVALID-PARAMETERS)
        (asserts! (and (> (len thematic-focus) u0) (< (len thematic-focus) u33)) ERR-INVALID-PARAMETERS)

        ;; Register showcase originator as primary participant
        (map-insert showcase-participation-registry
            {collection-sequence: next-collection-sequence, participant-entity: tx-sender}
            {
                participation-status: true,
                participation-start_block: block-height,
                originator-privilege: true
            }
        )

        ;; Integrate validated artifacts into the new showcase
        (map integrate-artifact-to-showcase (map transform-artifact-for-batch validated-artifacts))

        ;; Update global showcase sequence counter
        (var-set thematic-collection-sequence next-collection-sequence)

        (ok next-collection-sequence)
    )
)