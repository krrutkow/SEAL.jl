module SEAL
module libsealc
  # SEAL_jll provides `libsealc`, which we will use in this package
  using SEAL_jll
  using C
  using C: @cxx_cmd, @cxx_str
  
  let
    seal_path = SEAL_jll.get_libsealc_path() |> dirname |> dirname
    # @info "SEAL path" seal_path
    
    # For the actual include directory we need to first find the version-specific directory
    seal_include = joinpath(seal_path, "include")
    function get_version_include(include_dir)
      version_include = ""
      for dir in readdir(seal_include)
        if startswith(dir, "SEAL-")
          version_include = dir
          break
        end
      end
      return version_include
    end
    version_include = get_version_include(seal_include)
    if isempty(version_include)
      error("could not find proper include directory path in $seal_include")
    end
    seal_include = joinpath(seal_include, version_include)
    seal_include_c = joinpath(seal_include, "seal", "c")
    include_override = joinpath(@__DIR__, "include_override")
    # @info "SEAL include directory" seal_include
    # @info "SEAL C include directory" seal_include_c
    # @info "include override directory" include_override
    
    # Find header files to consider
    # headers = String["helper.h"]
    headers = String[]
    skip_headers = ["targetver.h"]
    for filename in readdir(seal_include_c)
      if !isfile(joinpath(seal_include_c, filename))
        continue
      end
      if !endswith(filename, ".h")
        continue
      end
      if filename in skip_headers
        continue
      end
      push!(headers, joinpath("seal", "c", filename))
    end
    # @info "Header files" headers
    
    # Build list of arguments for Clang
    clang_args = String[]
    include_directories = [seal_include]
    # include_directories = [seal_include, include_override]
    for dir in include_directories
      append!(clang_args, ("-I", dir))
    end
    
    cxx`-std=c++17 $(clang_args) -L$(dirname(SEAL_jll.get_libsealc_path())) -lsealc`
  end
  
  
  const cxx"int8_t" = Int8
  const cxx"int16_t" = Int16
  const cxx"int32_t" = Int32
  const cxx"int64_t" = Int64
  const cxx"uint8_t" = UInt8
  const cxx"uint16_t" = UInt16
  const cxx"uint32_t" = UInt32
  const cxx"uint64_t" = UInt64
  
  cxx"""
    #include <seal/c/defines.h>
    #include <seal/c/batchencoder.h>
    #include <seal/c/ciphertext.h>
    #include <seal/c/ckksencoder.h>
    #include <seal/c/contextdata.h>
    #include <seal/c/decryptor.h>
    #include <seal/c/encryptionparameterqualifiers.h>
    #include <seal/c/encryptionparameters.h>
    #include <seal/c/encryptor.h>
    #include <seal/c/evaluator.h>
    #include <seal/c/galoiskeys.h>
    #include <seal/c/keygenerator.h>
    #include <seal/c/kswitchkeys.h>
    #include <seal/c/memorymanager.h>
    #include <seal/c/memorypoolhandle.h>
    #include <seal/c/modulus.h>
    #include <seal/c/plaintext.h>
    #include <seal/c/publickey.h>
    #include <seal/c/relinkeys.h>
    #include <seal/c/sealcontext.h>
    #include <seal/c/secretkey.h>
    #include <seal/c/serialization.h>
    #include <seal/c/stdafx.h>
    #include <seal/c/valcheck.h>
    #include <seal/c/version.h>
  """j
end

using .libsealc
using C

"""
    SEALObject

Abstract parent type for all types based on SEAL classes.
"""
abstract type SEALObject end

"""
    gethandle(object::SEALObject)

Return the raw C pointer to where `object` resides in memory.
"""
@inline gethandle(object::SEALObject) = object.handle

"""
    sethandle!(object::SEALObject, handle)

Set the underlying raw C pointer to where `object` resides in memory to `handle`.
"""
@inline sethandle!(object::SEALObject, handle) = object.handle = handle

"""
    destroy!(object::SEALObject)

Call the corresponding destruction function on `object` to free up memory and reset object handle to
a null pointer. If `object` is not allocated, `destroy!` will not do anything.
"""
function destroy!(object::SEALObject) end

"""
    isnull(object::SEALObject)

Return true if the object handle is a null pointer and false otherwise.
"""
@inline isnull(object::SEALObject) = gethandle(object) == C_NULL

"""
    isallocated(object::SEALObject)

Return true if the object is allocated, i.e., if it is not null.
"""
@inline isallocated(object::SEALObject) = !isnull(object)

export SEALObject, gethandle, sethandle!, destroy!, isnull, isallocated

Base.unsafe_convert(::Type{Ptr{Cvoid}}, object::SEALObject) = gethandle(object)

include("auxiliary.jl")
# Julia-only auxiliary methods -> no exports

include("version.jl")
export version_major, version_minor, version_patch, version

include("modulus.jl")
export Modulus, SecLevelType, bit_count, value, coeff_modulus_create, coeff_modulus_bfv_default

include("serialization.jl")
export ComprModeType, SEALHeader, load_header!

include("encryptionparams.jl")
export EncryptionParameters, SchemeType, poly_modulus_degree,
       set_poly_modulus_degree!, set_coeff_modulus!, coeff_modulus,
       scheme, plain_modulus, set_plain_modulus!, plain_modulus_batching, parms_id, save!,
       save_size, load!

include("context.jl")
export SEALContext, first_parms_id, last_parms_id, get_context_data, key_context_data,
       first_context_data, parameter_error_message, using_keyswitching
export ContextData, chain_index, parms, parms_id, total_coeff_modulus_bit_count, qualifiers,
       next_context_data
export EncryptionParameterQualifiers, using_batching

include("publickey.jl")
export PublicKey, parms_id

include("secretkey.jl")
export SecretKey, parms_id, save!, load!

include("galoiskeys.jl")
export GaloisKeys, parms_id

include("relinkeys.jl")
export RelinKeys, parms_id, save_size, save!, load!

include("keygenerator.jl")
export KeyGenerator, create_public_key!, create_public_key, secret_key, create_relin_keys!,
       create_relin_keys, create_galois_keys!

include("plaintext.jl")
export Plaintext, scale, scale!, parms_id, to_string, save_size, save!

include("ciphertext.jl")
export Ciphertext, scale, scale!, parms_id, size, length, save_size, save!, load!, reserve!

include("encryptor.jl")
export Encryptor, set_secret_key!, encrypt!, encrypt_symmetric, encrypt_symmetric!

include("evaluator.jl")
export Evaluator, square!, square_inplace!, relinearize!, relinearize_inplace!, rescale_to_next!,
       rescale_to_next_inplace!, multiply_plain!, multiply_plain_inplace!, multiply!,
       multiply_inplace!, mod_switch_to!, mod_switch_to_inplace!, mod_switch_to_next!,
       mod_switch_to_next_inplace!, add!, add_inplace!, add_plain!, add_plain_inplace!,
       rotate_vector!, rotate_vector_inplace!, rotate_rows!, rotate_rows_inplace!,
       rotate_columns!, rotate_columns_inplace!, complex_conjugate!, complex_conjugate_inplace!,
       negate!

include("decryptor.jl")
export Decryptor, decrypt!, invariant_noise_budget

include("ckks.jl")
export CKKSEncoder, slot_count, encode!, decode!

include("batchencoder.jl")
export BatchEncoder, slot_count, encode!, decode!

include("memorymanager.jl")
export MemoryPoolHandle, alloc_byte_count, memory_manager_get_pool


end
