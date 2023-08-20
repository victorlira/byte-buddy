package net.bytebuddy.agent;

import com.sun.jna.Library;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Platform;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.Psapi;
import com.sun.jna.platform.win32.WinDef;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.win32.StdCallLibrary;
import com.sun.jna.win32.W32APIOptions;
import net.bytebuddy.agent.utility.nullability.MaybeNull;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

abstract class Unsolver<T, S> {

	void enableDynamicAgentLoading(long pid) {
		T targetProcess = openProcess(pid);
		S jvm = null;
		try {
			jvm = findLibJvm(targetProcess);
			boolean is64bit = is64Bit(targetProcess);
			int targetSize = is64bit ? 8 : 4;
			SymbolLookup<T, S> lookup = new SymbolLookup<T, S>(this, targetProcess, jvm, is64bit);
			Map<String, Map<String, Field>> map = new HashMap<String, Map<String, Field>>();
			{
				long entry = lookup.getSymbol("gHotSpotVMStructs");
				long typeNameOffset = lookup.getSymbol("gHotSpotVMStructEntryTypeNameOffset");
				long fieldNameOffset = lookup.getSymbol("gHotSpotVMStructEntryFieldNameOffset");
				long stride = lookup.getSymbol("gHotSpotVMStructEntryArrayStride");
				long isStaticOffset = lookup.getSymbol("gHotSpotVMStructEntryIsStaticOffset");
				long addressOffset = lookup.getSymbol("gHotSpotVMStructEntryAddressOffset");
				long offsetOffset = lookup.getSymbol("gHotSpotVMStructEntryOffsetOffset");
				HotSpotTraverse<T> traverse = new HotSpotTraverse<T>(
						this,
						targetProcess,
						targetSize,
						typeNameOffset,
						fieldNameOffset,
						isStaticOffset,
						addressOffset,
						offsetOffset
				);
				while (true) {
					String fieldName = traverse.getFieldName(entry);
					if (fieldName == null) {
						break;
					}
					String typeName = traverse.getTypeName(entry);
					boolean isStatic = traverse.isStatic(entry);
					long offset = isStatic ? traverse.getAddress(entry) : traverse.getOffset(entry);
					if (!map.containsKey(typeName)) {
						map.put(typeName, new HashMap<String, Field>());
					}
					map.get(typeName).put(fieldName, new Field(offset, isStatic));
					entry += stride;
				}
			}
			String flagTypeName = "Flag";
			Map<String, Field> type = map.get(flagTypeName);
			if (type == null) {
				flagTypeName = "JVMFlag";
				type = map.get(flagTypeName);
			}
			{
				long entry = lookup.getSymbol("gHotSpotVMTypes");
				long typeNameOffset = lookup.getSymbol("gHotSpotVMTypeEntryTypeNameOffset");
				long sizeOffset = lookup.getSymbol("gHotSpotVMTypeEntrySizeOffset");
				long stride = lookup.getSymbol("gHotSpotVMTypeEntryArrayStride");
				HotSpotTraverse<T> traverse = new HotSpotTraverse<T>(
						this,
						targetProcess,
						targetSize,
						typeNameOffset,
						0L,
						0L,
						0L,
						sizeOffset
				);
				String typeName;
				while ((typeName = traverse.getTypeName(entry)) != null) {
					if (flagTypeName.equals(typeName)) {
						int size = traverse.getOffset(entry);
						long numFlags = type.get("numFlags").offset;
						Memory memory = new Memory(1024);
						readProcessMemory(targetProcess, Pointer.createConstant(numFlags), memory, 4);
						int flagCount = memory.getInt(0);
						readProcessMemory(targetProcess, Pointer.createConstant(type.get("flags").offset), memory, targetSize);
						Pointer baseFlagAddress = readPointer(memory, targetSize);
						long _name = type.get("_name").offset;
						long _addr = type.get("_addr").offset;
						for (int k = 0; k < flagCount - 1; k++) {
							Pointer flagAddress = baseFlagAddress.share((long) k * size);
							readProcessMemory(targetProcess, flagAddress.share(_name), memory, targetSize);
							Pointer pointer = readPointer(memory, targetSize);
							readProcessMemory(targetProcess, pointer, memory, 1024);
							String flagName = readStringA(memory, 1024);
							if ("EnableDynamicAgentLoading".equals(flagName)) {
								readProcessMemory(targetProcess, flagAddress.share(_addr), memory, targetSize);
								Pointer valueAddress = readPointer(memory, targetSize);
								memory.setByte(0L, (byte) 1);
								writeProcessMemory(targetProcess, valueAddress, memory, 1);
								return;
							}
						}
					}
					entry += stride;
				}
			}
		} finally {
			if (jvm != null) {
				closeLibJvm(jvm);
			}
			closeProcess(targetProcess);
		}
		throw new IllegalStateException("Could not change EnableDynamicAgentLoading flag");
	}

	abstract T openProcess(long pid);

	abstract boolean is64Bit(T handle);

	abstract boolean closeProcess(T handle);

	abstract S findLibJvm(T process);

	abstract void closeLibJvm(S module);

	abstract Pointer getProcAddress(S module, String name);

	abstract int readProcessMemory(T process, Pointer src, Pointer dst, int size);

	abstract int writeProcessMemory(T process, Pointer dst, Pointer src, int size);

	@MaybeNull
	private static Pointer readPointer(Pointer from, int ptrSize) {
		long raw = ptrSize == 8 ? from.getLong(0) : from.getInt(0);
		if (raw == 0L) return null;
		return new Pointer(raw);
	}

	private static String readStringA(Pointer pointer, int size) {
		char[] buf = new char[32];
		int i;
		for (i = 0; i < size; i++) {
			byte b = pointer.getByte(i);
			if (b == 0) {
				break;
			}
			if (i == buf.length) {
				char[] copy = new char[i + 16];
				System.arraycopy(buf, 0, copy, 0, buf.length);
				buf = copy;
			}
			buf[i] = (char) b;
		}
		return new String(buf, 0, i);
	}

	static class ForLinux extends Unsolver<Integer, ForLinux.NativeLib> {

		public Integer openProcess(long pid) {
			int result = LibC.INSTANCE.ptrace(16 /* PTRACE_ATTACH */, (int) pid, null, null);
			if (result != -1) {
				throw new IllegalStateException("PTRACE_ATTACH failed");
			}
			LibC.INSTANCE.waitpid((int) pid, new IntByReference(), 0);
			return (int) pid;
		}

		public boolean is64Bit(Integer handle) {
			return Platform.is64Bit();
		}

		public boolean closeProcess(Integer handle) {
			LibC.INSTANCE.ptrace(17 /* PTRACE_DETACH */, handle, null, null);
			return true;
		}

		public NativeLib findLibJvm(Integer process) {
			try {
				BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream("/proc/" + process + "/maps"), "UTF-8"));
				try {
					String line;
					while ((line = reader.readLine()) != null) {
						if (line.contains("libjvm.so")) {
							String path = line.substring(line.indexOf('/'));
							LinkMap handle = LibC.INSTANCE.dlopen(path, 1 /* RTLD_LAZY */);
							return new NativeLib(
									Long.parseLong(line.substring(0, line.indexOf('-')), 16),
									path,
									handle
							);
						}
					}
				} finally {
					reader.close();
				}
			} catch (IOException e) {
				throw new IllegalStateException(e);
			}
			return null;
		}

		public void closeLibJvm(NativeLib module) {
			LibC.INSTANCE.dlclose(module.handle.getPointer());
		}

		public Pointer getProcAddress(NativeLib module, String name) {
			Pointer pointer = LibC.INSTANCE.dlsym(module.handle.getPointer(), name);
			long raw = Pointer.nativeValue(pointer);
			long ourBase = Pointer.nativeValue(module.handle.l_addr);
			long dstBase = module.base;
			long result = raw - ourBase + dstBase;
			return new Pointer(result);
		}

		public int readProcessMemory(Integer process, Pointer src, Pointer dst, int size) {
			iovec local_iov = new iovec();
			local_iov.iov_base = dst;
			local_iov.iov_len = size;

			iovec remote_iov = new iovec();
			remote_iov.iov_base = src;
			remote_iov.iov_len = size;

			int result = LibC.INSTANCE.process_vm_readv(process, new iovec[]{local_iov}, 1, new iovec[]{remote_iov}, 1, 0);
			if (result == -1) {
				throw new IllegalStateException("process_vm_readv failed " + Native.getLastError());
			}
			return result;
		}

		public int writeProcessMemory(Integer process, Pointer dst, Pointer src, int size) {
			iovec local_iov = new iovec();
			local_iov.iov_base = src;
			local_iov.iov_len = size;

			iovec remote_iov = new iovec();
			remote_iov.iov_base = dst;
			remote_iov.iov_len = size;

			int result = LibC.INSTANCE.process_vm_writev(process, new iovec[]{local_iov}, 1, new iovec[]{remote_iov}, 1, 0);
			if (result == -1) {
				throw new IllegalStateException("process_vm_writev failed"  + Native.getLastError());
			}
			return result;
		}

		private interface LibC extends Library {

			LibC INSTANCE = Native.load("c", LibC.class);

			int ptrace(int __ptrace_request, int pid, Pointer address, Pointer data);

			int waitpid(int pid, IntByReference status, int options);

			LinkMap dlopen(String fileName, int flags);

			Pointer dlsym(Pointer handle, String symbol);

			int dlclose(Pointer handle);

			int process_vm_readv(int pid, iovec[] local_iov, int liovcnt, iovec[] remote_iov, int riovcnt, long flags);

			int process_vm_writev(int pid, iovec[] local_iov, int liovcnt, iovec[] remote_iov, int riovcnt, long flags);
		}

		private static final class NativeLib {
			final long base;
			final String path;
			final LinkMap handle;

			NativeLib(long base, String path, LinkMap handle) {
				this.base = base;
				this.path = path;
				this.handle = handle;
			}
		}

		public static class LinkMap extends Structure {
			public static final class LinkMapRef extends LinkMap implements ByReference {
			}

			private static final List<String> ORDER = Arrays.asList("l_addr", "l_name", "l_ld", "l_next", "l_prev");
			public Pointer l_addr;
			public String l_name;
			public Pointer l_ld;
			public LinkMapRef l_next;
			public LinkMapRef l_prev;

			public LinkMap() {
			}

			public LinkMap(Pointer p) {
				super(p);
			}

			@Override
			protected List<String> getFieldOrder() {
				return ORDER;
			}
		}

		public static final class iovec extends Structure {
			private static final List<String> ORDER = Arrays.asList("iov_base", "iov_len");
			public Pointer iov_base;
			public long iov_len;

			@Override
			protected List<String> getFieldOrder() {
				return ORDER;
			}
		}
	}

	static class ForWindowsProcess extends Unsolver<WinNT.HANDLE, ForWindowsProcess.Lib> {

		public WinNT.HANDLE openProcess(long pid) {
			return Kernel32.INSTANCE.OpenProcess(
					0x0008 | 0x0010 | 0x0020,
					false,
					(int) pid
			);
		}

		public boolean is64Bit(WinNT.HANDLE handle) {
			IntByReference ref = new IntByReference();
			if (!Kernel32.INSTANCE.IsWow64Process(handle, ref)) {
				throw new IllegalStateException("IsWow64Process");
			}
			return ref.getValue() == 0;
		}

		public boolean closeProcess(WinNT.HANDLE handle) {
			return Kernel32.INSTANCE.CloseHandle(handle);
		}

		public ForWindowsProcess.Lib findLibJvm(WinNT.HANDLE process) {
			int pointerSize = Native.POINTER_SIZE;
			WinDef.HMODULE[] modules = new WinDef.HMODULE[512];
			IntByReference ref = new IntByReference();
			if (!Psapi.INSTANCE.EnumProcessModules(
					process,
					modules,
					512 * pointerSize,
					ref
			)) {
				throw new IllegalStateException();
			}
			char[] pathBuf = new char[260];
			for (int i = 0, j = ref.getValue() / pointerSize; i < j; i++) {
				WinDef.HMODULE moduleHandle = modules[i];
				int len = Psapi.INSTANCE.GetModuleFileNameExW((WinNT.HANDLE) process, moduleHandle, pathBuf, 260);
				if (len != 0) {
					throw new IllegalStateException("GetModuleFileNameExA");
				}
				String moduleName = new String(pathBuf, 0, len);
				if (moduleName.contains("jvm.dll")) {
					WinDef.HMODULE lib = Kernel32.INSTANCE.LoadLibraryEx(moduleName, null, 0x00000001 /* DONT_RESOLVE_DLL_REFERENCES */);
					return new Lib(lib, moduleHandle);
				}
			}
			throw new IllegalStateException();
		}

		public void closeLibJvm(ForWindowsProcess.Lib module) {
			Kernel32.INSTANCE.CloseHandle(module.ourHandle);
		}

		public Pointer getProcAddress(ForWindowsProcess.Lib module, String name) {
			WinDef.LPVOID address = Kernel32Ext.INSTANCE.GetProcAddress(module.ourHandle, name);
			long raw = Pointer.nativeValue(address.getPointer());
			long ourBase = Pointer.nativeValue(module.ourHandle.getPointer());
			long dstBase = Pointer.nativeValue(module.theirHandle.getPointer());
			long result = raw - ourBase + dstBase;
			return new Pointer(result);
		}

		public int readProcessMemory(WinNT.HANDLE process, Pointer src, Pointer dst, int size) {
			IntByReference read = new IntByReference();
			if (!Kernel32.INSTANCE.ReadProcessMemory(process, src, dst, size, read)) {
				throw new IllegalStateException();
			}
			return read.getValue();
		}

		public int writeProcessMemory(WinNT.HANDLE process, Pointer dst, Pointer src, int size) {
			IntByReference written = new IntByReference();
			if (!Kernel32.INSTANCE.WriteProcessMemory(process, dst, src, size, written)) {
				throw new IllegalStateException();
			}
			return written.getValue();
		}

		public interface Kernel32Ext extends StdCallLibrary {

			Kernel32Ext INSTANCE = Native.load("kernel32", Kernel32Ext.class, W32APIOptions.ASCII_OPTIONS);

			WinDef.LPVOID GetProcAddress(WinDef.HMODULE hModule, String lpProcName);
		}

		private static final class Lib {
			final WinDef.HMODULE ourHandle;
			final WinDef.HMODULE theirHandle;

			Lib(WinDef.HMODULE ourHandle, WinDef.HMODULE theirHandle) {
				this.ourHandle = ourHandle;
				this.theirHandle = theirHandle;
			}
		}
	}

	private static final class Field {
		final long offset;
		final boolean isStatic;

		Field(long offset, boolean isStatic) {
			this.offset = offset;
			this.isStatic = isStatic;
		}
	}

	private static final class HotSpotTraverse<T> {
		final Unsolver<T, ?> access;
		final T process;
		final int pointerSize;
		final long typeNameOffset;
		final long fieldNameOffset;
		final long isStaticOffset;
		final long addressOffset;
		final long offsetOffset;
		final Memory memory;

		HotSpotTraverse(Unsolver<T, ?> access, T process, int pointerSize, long typeNameOffset, long fieldNameOffset, long isStaticOffset, long addressOffset, long offsetOffset) {
			this.access = access;
			this.process = process;
			this.pointerSize = pointerSize;
			this.typeNameOffset = typeNameOffset;
			this.fieldNameOffset = fieldNameOffset;
			this.isStaticOffset = isStaticOffset;
			this.addressOffset = addressOffset;
			this.offsetOffset = offsetOffset;
			memory = new Memory(1024);
		}

		String getTypeName(long entry) {
			return getStringAt(entry, typeNameOffset);
		}

		String getFieldName(long entry) {
			return getStringAt(entry, fieldNameOffset);
		}

		boolean isStatic(long entry) {
			access.readProcessMemory(process, Pointer.createConstant(entry + isStaticOffset), memory, 4);
			return memory.getInt(0) == 1;
		}

		int getOffset(long entry) {
			access.readProcessMemory(process, Pointer.createConstant(entry + offsetOffset), memory, 4);
			return memory.getInt(0);
		}

		long getAddress(long entry) {
			access.readProcessMemory(process, Pointer.createConstant(entry + addressOffset), memory, pointerSize);
			return pointerSize == 8 ? memory.getLong(0) : memory.getInt(0);
		}

		private String getStringAt(long entry, long offset) {
			access.readProcessMemory(process, Pointer.createConstant(entry + offset), memory, pointerSize);
			Pointer ptr = readPointer(memory, pointerSize);
			if (ptr == null) {
				return null;
			}
			int bytesRead = access.readProcessMemory(process, ptr, memory, 1024);
			return readStringA(memory, bytesRead);
		}
	}

	private static final class SymbolLookup<T, S> {

		final Unsolver<T, S> access;
		final S module;
		final T process;
		final boolean is64bit;
		private final Memory tmp;

		SymbolLookup(Unsolver<T, S> access, T process, S module, boolean is64bit) {
			this.access = access;
			this.process = process;
			this.module = module;
			this.is64bit = is64bit;
			tmp = new Memory(8);
		}

		long getSymbol(String name) {
			Pointer ptr = access.getProcAddress(module, name);
			Memory tmp = this.tmp;
			access.readProcessMemory(process, ptr, tmp, is64bit ? 8 : 4);
			return is64bit ? tmp.getLong(0) : tmp.getInt(0);
		}
	}
}
