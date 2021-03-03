
"""
    RelinKeys

Stores relinearization keys generated by a `KeyGenerator` instance.

See also: [`KeyGenerator`](@ref)
"""
mutable struct RelinKeys <: SEALObject
  handle::Ptr{Cvoid}

  function RelinKeys()
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    # RelinKeys are created as KSwitchKeys since they share the same data
    retval = ccall((:KSwitchKeys_Create1, libsealc), Clong,
                   (Ref{Ptr{Cvoid}},),
                   handleref)
    @check_return_value retval
    return RelinKeys(handleref[])
  end

  function RelinKeys(handle::Ptr{Cvoid})
    object = new(handle)
    finalizer(destroy!, object)
    return object
  end
end

function destroy!(object::RelinKeys)
  if isallocated(object)
    @check_return_value ccall((:KSwitchKeys_Destroy, libsealc), Clong, (Ptr{Cvoid},), object)
    sethandle!(object, C_NULL)
  end

  return nothing
end

function parms_id(key::RelinKeys)
  parms_id = zeros(UInt64, 4)
  retval = ccall((:KSwitchKeys_GetParmsId, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{UInt64}),
                 key, parms_id)
  @check_return_value retval
  return parms_id
end

function save_size(compr_mode, key::RelinKeys)
  result = Ref{Int64}(0)
  retval = ccall((:KSwitchKeys_SaveSize, libsealc), Clong,
                 (Ptr{Cvoid}, UInt8, Ref{Int64}),
                 key, compr_mode, result)
  @check_return_value retval
  return Int(result[])
end
save_size(key::RelinKeys) = save_size(ComprModeType.default, key)

function save!(buffer::DenseVector{UInt8}, length::Integer,
               compr_mode::ComprModeType.ComprModeTypeEnum, key::RelinKeys)
  out_bytes = Ref{Int64}(0)
  retval = ccall((:KSwitchKeys_Save, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{UInt8}, UInt64, UInt8, Ref{Int64}),
                 key, buffer, length, compr_mode, out_bytes)
  @check_return_value retval
  return Int(out_bytes[])
end
function save!(buffer::DenseVector{UInt8}, length::Integer, key::RelinKeys)
  return save!(buffer, length, ComprModeType.default, key)
end
function save!(buffer::DenseVector{UInt8}, key::RelinKeys)
  return save!(buffer, length(buffer), key)
end

function load!(key::RelinKeys, context::SEALContext, buffer::DenseVector{UInt8}, length)
  in_bytes = Ref{Int64}(0)
  retval = ccall((:KSwitchKeys_Load, libsealc), Clong,
                 (Ptr{Cvoid}, Ptr{Cvoid}, Ref{UInt8}, UInt64, Ref{Int64}),
                 key, context, buffer, length, in_bytes)
  @check_return_value retval
  return Int(in_bytes[])
end
load!(key::RelinKeys, context::SEALContext, buffer::DenseVector{UInt8}) = load!(key,
                                                                                context,
                                                                                buffer,
                                                                                length(buffer))

