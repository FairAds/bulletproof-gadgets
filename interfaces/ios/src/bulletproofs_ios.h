#include <stdint.h>
#include <stdbool.h>

struct ProofArtifacts {
    const char* commitments;
    const int8_t* proof;
    int proof_len;
    int proof_cap;
};

const struct ProofArtifacts* c_prove(const char* name, const char* instance, const char* witness, const char* gadgets);
const bool c_verify(const char* name, const char* instance, const char* gadgets, const char* commitments, const uint8_t* proof, int proof_len);
void free_proof(struct ProofArtifacts* artifacts_pointer);
