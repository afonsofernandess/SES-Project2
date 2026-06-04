// System headers
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
// #include <bsd/string.h>

// PWM header
#include "pwm.h"

static pwm_node_t* create_node(char* user, salt_t salt, hash_t hash) {
  pwm_node_t* node = (pwm_node_t*) malloc(sizeof(pwm_node_t));
  strncpy(node -> user, user, sizeof(node -> user) - 1);
  node -> user[sizeof(node -> user) - 1] = '\0';
  memcpy(node -> salt, salt, sizeof(node -> salt));
  memcpy(node -> hash, hash, sizeof(node -> hash));
  node -> next = NULL;
  return node;
}

static pwm_res_t create_node_p(char* user, char* password, pwm_node_t** node) {
   salt_t salt;
   hash_t hash;
   pwm_res_t r = PWM_OK;
   if ( (r = pwm_generate_salt(salt)) == PWM_OK
       && (r = pwm_hash_password(user,salt, password, hash)) == PWM_OK) {
      *node = create_node(user, salt, hash);
   }
   return r;
}


static pwm_res_t pwm_alloc(char* file, PWM* p_pwm) {
  PWM pwm = (PWM) malloc(sizeof(struct _pwm_t));
  if (pwm == NULL) {
    perror("malloc");
    pwm_error("Could not allocate memory!");
    return PWM_MEMORY_ALLOCATION_ERROR;
  }
  pwm -> file = strdup(file);
  if (pwm -> file == NULL) {
    free(pwm);
    perror("strdup");
    pwm_error("Could not allocate memory!");
    return PWM_MEMORY_ALLOCATION_ERROR;
  }
  pwm -> entries = NULL;
  *p_pwm = pwm;
  return PWM_OK;
}

pwm_res_t pwm_free(PWM pwm) {
  pwm_node_t* node = pwm -> entries;
  while (node != NULL) {
    pwm_node_t* aux = node;
    node = node -> next;
    free(aux);
  }
  free(pwm -> file);
  free(pwm);
  return PWM_OK;
}

pwm_res_t pwm_init(char* file, char* password, PWM* pwm) {
  pwm_res_t r = PWM_OK;
  if ((r = pwm_is_valid_password(password)) != PWM_OK) {
    pwm_error("Invalid password '%s'!", password);
    return r;
  }
  if ((r = pwm_alloc(file, pwm)) != PWM_OK) {
    return r;
  }
  // adiciona aqui a chave para encriptar e desencriptar
  pwn_derive_key(password, (*pwm)->key);
  return create_node_p(PWM_ADMIN_USER, password, &((*pwm) -> entries));
}

pwm_res_t pwm_open(char* file, char* password, PWM* pwm) {
  pwm_res_t r = PWM_OK;
  FILE* f = fopen(file, "rb");
  if (f == NULL) {
    *pwm = NULL;
    r = PWM_FILE_INACESSIBLE;
    perror(file);
    pwm_error("Could not open file '%s' for reading!", file);
  } else if ((r = pwm_alloc(file, pwm)) == PWM_OK) {
    pwn_derive_key(password, (*pwm)->key);
    unsigned char iv[AES_IV];
    unsigned char tag[AES_TAG];
    int ciphertext_len = 0;

    if ((fread(iv, 1, AES_IV, f) != AES_IV) || (fread(tag, 1, AES_TAG, f) != AES_TAG) || 
        (fread(&ciphertext_len, sizeof(int), 1, f) != 1)) {
        
      pwm_error("Metadata wrong!");
      pwm_free(*pwm);
      *pwm = NULL;
      fclose(f);
      return PWM_FILE_CORRUPT;
    }

    unsigned char* ciphertext = malloc(ciphertext_len);
    if (!ciphertext) {
      pwm_free(*pwm);
      *pwm = NULL;
      fclose(f);
      return PWM_MEMORY_ALLOCATION_ERROR;
    }
    if (fread(ciphertext, 1, ciphertext_len, f) != ciphertext_len) {
      pwm_error("Corrupted file!");
      free(ciphertext);
      pwm_free(*pwm);
      *pwm = NULL;
      fclose(f);
      return PWM_FILE_CORRUPT;
    }
    fclose(f); // Fechar o ficheiro logo após a leitura do ciphertext

    // comeca a decifrar
    unsigned char* plaintext = malloc(ciphertext_len + 1); // +1 para o terminador nulo '\0'
    if (!plaintext) {
      free(ciphertext);
      pwm_free(*pwm);
      *pwm = NULL;
      return PWM_MEMORY_ALLOCATION_ERROR;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len = 0;

    if (!ctx || EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, (*pwm)->key, iv) != 1) {
      r = PWM_OS_ERROR;
    } else {
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG, tag);

      if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        r = PWM_PASSWORD_MISMATCH; 
      } else {

        plaintext_len = len;
        if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
          r = PWM_PASSWORD_MISMATCH;
        } else {
          plaintext_len += len;
          plaintext[plaintext_len] = '\0';
        }
      }
    }

    if (ctx) 
      EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);

    if (r != PWM_OK) {
      free(plaintext);
      pwm_free(*pwm);
      *pwm = NULL;
      pwm_error("Decryption failed! Wrong password or corrupted file.");
      return r;
    }

    char line[1024];
    int count = 0;
    pwm_node_t* curr = NULL;
    char* line_start = (char*) plaintext;
    char* line_end;

    while (line_start != NULL && *line_start != '\0') {
      line_end = strchr(line_start, '\n');
      size_t line_length = line_end ? (size_t)(line_end - line_start) : strlen(line_start);
      
      if (line_length >= sizeof(line)) {
        r = PWM_FILE_CORRUPT;
        pwm_error("Corrupted file! Line too long.");
        break;
      }
      strncpy(line, line_start, line_length);
      line[line_length] = '\0';
      line_start = line_end ? (line_end + 1) : NULL;
      char* line_fields[3];
      char* user, *salt_str, *hash_str;
      salt_t salt;
      hash_t hash;
      pwm_node_t* node;
      count++;
      if (pwm_split_line(line, ':', line_fields, 3) != 3) {
        r = PWM_FILE_CORRUPT;
        pwm_error("Corrupted file! Wrong line format.");
        break;
      }
      user = line_fields[0];
      salt_str = line_fields[1];
      hash_str = line_fields[2];

      if (! pwm_decode_hex_string(salt_str, salt, sizeof(salt_t))) {
        pwm_error("Corrupt file '%s' at line %d [salt] !", (*pwm)->file, count);
        r = PWM_FILE_CORRUPT;
        break;
      }
      if (! pwm_decode_hex_string(hash_str, hash, sizeof(hash_t))) {
        pwm_error("Corrupt file '%s' at line %d [hash] !", (*pwm)->file, count);
        r = PWM_FILE_CORRUPT;
        break;
      }
      node = create_node(user, salt, hash);
      if (count == 1) {
        hash_t vhash;
        pwm_hash_password(node -> user, node -> salt, password, vhash);
        if (memcmp(node -> hash, vhash, sizeof(hash_t)) != 0) {
          r = PWM_PASSWORD_MISMATCH;
          pwm_error("Password mismatch for admin user!");
          free(node);
          break;
        }
        if (strcmp(node->user, PWM_ADMIN_USER) != 0) {
          r = PWM_FILE_CORRUPT;
          pwm_error("First entry is not admin user!");
          free(node);
          break;
        }
        (*pwm) -> entries = node;
      } else {
        curr -> next = node;
      }  
      curr = node;
    }

    free(plaintext); // Liberta o plaintext FORA do ciclo while
    if (r != PWM_OK) {
      pwm_free(*pwm); 
      *pwm = NULL;
    }
  }    
  return r; 
}

pwm_res_t pwm_update(PWM pwm, char* user, char* password) {
  int r = PWM_OK;
  if ((r = pwm_is_valid_password(password)) == PWM_OK) {
    pwm_node_t* node = pwm -> entries;
    while (node != NULL) {
      if ( strcmp(node -> user, user) == 0) {
        salt_t salt;
        hash_t hash;
        if ( (r = pwm_generate_salt(salt)) == PWM_OK
           && (r = pwm_hash_password(user, salt, password, hash)) == PWM_OK) {
          memcpy(node -> salt, salt, sizeof(salt));
          memcpy(node -> hash, hash, sizeof(hash));

          // se for o admin, temos que mudar a chave de encript tambem 
          if (strcmp(user, PWM_ADMIN_USER) == 0) {
            pwn_derive_key(password, pwm->key);
          }
        }
        break;
      }
      node = node -> next;
    }
    if (node == NULL) {
      r = PWM_USER_NOT_FOUND;
      pwm_error("User '%s' does not exist!", user);
    }  
  } else {
    pwm_error("Invalid password '%s'!", password);
  }
  return r;
}

pwm_res_t pwm_add(PWM pwm, char* user, char* password) {
  pwm_res_t r = PWM_OK;
  if ( strcmp(user, PWM_ADMIN_USER) == 0) {
    r = PWM_OPERATION_NOT_ALLOWED;
    pwm_error("User '%s' cannot be added!", user);
  }
  else if ((r = pwm_is_valid_user(user)) != PWM_OK) {
    pwm_error("Invalid user id '%s'!", user);
  } else if ((r = pwm_is_valid_password(password)) != PWM_OK) {
    pwm_error("Invalid password '%s'!", password);
  } else {
    pwm_node_t* node = pwm -> entries;
    while (node -> next != NULL) {
      if (strcmp(node -> next -> user, user) == 0) {
        pwm_error("User '%s' already exists!", user);
        r = PWM_USER_ALREADY_EXISTS;
        break;
      }
      node = node -> next;
    }
    if (node -> next == NULL) {
      r = create_node_p(user, password, & (node -> next));
    }
  }
  return r;
}

pwm_res_t pwm_delete(PWM pwm, char* user) {
  pwm_res_t r = PWM_OK;
  if ( strcmp(user, PWM_ADMIN_USER) == 0) {
    pwm_error("User '%s' cannot be deleted!", user);
    r = PWM_OPERATION_NOT_ALLOWED;
  } else {
    pwm_node_t* node = pwm -> entries;
    while (node -> next != NULL) {
      if (strcmp(node -> next -> user, user) == 0) {
        break;
      }
      node = node -> next;
    }
    if (node -> next == NULL) {
      r = PWM_USER_NOT_FOUND;
      pwm_error("User '%s' does not exist!", user);
    } else {
      pwm_node_t* temp = node -> next;
      node -> next = temp -> next;
      free(temp);
    } 
  }
  return r;
}

pwm_res_t pwm_save(PWM pwm) {
  //parte da AEAD
  size_t buffer_size = 1024;
  char* plaintext = malloc(buffer_size);
  if (plaintext == NULL) {
    pwm_error("Could not allocate memory!");
    return PWM_MEMORY_ALLOCATION_ERROR;
  }
  size_t offset = 0;
  plaintext[0] = '\0';

  pwm_node_t* node = pwm -> entries;
  while (node != NULL) {
    if(offset + strlen(node -> user) + 1 + 2*sizeof(salt_t) + 1 + 2*sizeof(hash_t) + 1 > buffer_size) {
      buffer_size *= 2;
      char* new_plaintext = realloc(plaintext, buffer_size);
      if (new_plaintext == NULL) {
        free(plaintext);
        perror("realloc");
        pwm_error("Could not allocate memory!");
        return PWM_MEMORY_ALLOCATION_ERROR;
      }
      plaintext = new_plaintext;
    }

    char salt_hex[2*sizeof(salt_t) + 1];
    char hash_hex[2*sizeof(hash_t) + 1];
    pwn_store_hex_string(salt_hex, node -> salt, sizeof(salt_t));
    pwn_store_hex_string(hash_hex, node -> hash, sizeof(hash_t));

    //adiciona ao buffer user:salt:hash\n
    offset += sprintf(plaintext + offset, "%s:%s:%s\n", node -> user, salt_hex, hash_hex);
    node = node -> next;
  } 

  unsigned char iv[AES_IV];
  unsigned char tag[AES_TAG];
  unsigned char* ciphertext = malloc(offset);
  if (ciphertext == NULL) {
    free(plaintext);
    perror("malloc");
    pwm_error("Could not allocate memory!");
    return PWM_MEMORY_ALLOCATION_ERROR;
  }

  if(RAND_bytes(iv, sizeof(iv)) != 1) {
    free(plaintext);
    free(ciphertext);
    return PWM_OS_ERROR;
  }

  int len, ciphertext_len = 0;
  //aead com AES-GCM
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if(!ctx) {
    free(plaintext);
    free(ciphertext);
    return PWM_OS_ERROR;
  }

  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
      EVP_EncryptInit_ex(ctx, NULL, NULL, pwm->key, iv) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    free(plaintext);
    free(ciphertext);
    return PWM_OS_ERROR;
  }

  // Cifrar os dados
  if (EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)plaintext, offset) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    free(plaintext);
    free(ciphertext);
    return PWM_OS_ERROR;
  }
  ciphertext_len = len;

  if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    free(plaintext);
    free(ciphertext);
    return PWM_OS_ERROR;
  }
  ciphertext_len += len;

  // tag de autenticação 
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG, tag) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    free(plaintext);
    free(ciphertext);
    return PWM_OS_ERROR;
  }

  EVP_CIPHER_CTX_free(ctx);
  free(plaintext);

  FILE* f = fopen(pwm->file, "wb");
  if (!f) {
    perror(pwm->file);
    free(ciphertext);
    pwm_error("Could not open file '%s' for writing!", pwm->file);
    return PWM_IO_ERROR;
  }
  // Escreve os metadados 
  fwrite(iv, 1, AES_IV, f);                    // IV (12 bytes)
  fwrite(tag, 1, AES_TAG, f);                  // Tag (16 bytes)
  fwrite(&ciphertext_len, sizeof(int), 1, f);   // Tamanho do texto cifrado
  fwrite(ciphertext, 1, ciphertext_len, f);    // Texto cifrado

  fclose(f);
  free(ciphertext);
  return PWM_OK; 
}

pwm_res_t pwm_iterate(PWM pwm, pwm_iterator_t* iterator, void* arg) {
  pwm_res_t r = PWM_OK;
  pwm_node_t* node = pwm -> entries;
  while (node != NULL && r == PWM_OK) {
    r = iterator(node -> user, node -> salt, node -> hash, arg);
    node = node -> next;
  }
  return r;
}

pwm_res_t pwm_match(PWM pwm, char* user, char* password) {
  pwm_node_t* node = pwm -> entries;
  pwm_res_t r = PWM_OK;
  hash_t hash;
  while (node != NULL) {
    if ( strcmp(node -> user, user) == 0) {
      break;
    }
    node = node -> next;
  }
  if (node == NULL) {
    pwm_error("User '%s' does not exist!", user);
    r = PWM_USER_NOT_FOUND;
  } 
  else 
  if ((r = pwm_hash_password(user, node -> salt, password, hash)) == PWM_OK) {
    if (memcmp(node -> hash, hash, sizeof(hash_t)) != 0) {
      pwm_error("Password mismatch for user '%s'!", user);
      r = PWM_PASSWORD_MISMATCH; 
    }
  }  
  return r;
}

