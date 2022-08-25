---
layout: post
title:  "Partially Defeating .Net Reactor's Necrobit With This Simple Trick."
date:   2021-08-06 09:29:20 +0300
tags: [C#, .NET, Reverse Engineering, .NET Reactor, Necrobit, JIT, Obfuscation, Deobfuscation]
categories: [.NET Reactor]
---
I recently came across a post on [tuts4you](https://forum.tuts4you.com/topic/42709-net-reactor-v6500/?do=findComment&comment=206933) which basically said that .net reactor uses a hashtable to store pre-`JIT` information about methods that use Necrobit and wanted to see what it is all about for myself.

### The sample
![Sample](../../assets/img/defeating-reactors-necrobit/sample.png)
We will be using a simple .NET Framework 4.8 x86 test application on RELEASE mode with .NET Reactor v.6.7.0.0 Demo and just Necrobit with compatibility mode disabled.

### The goal
The goal is to dump and recompile the `CIL` code of certain methods.
![Goal](../../assets/img/defeating-reactors-necrobit/goal.png)

### How does Necrobit work?
Necrobit encrypts the method body bytes beforehand and decrypts them at runtime. It hooks the `JIT` compiler and replaces them in memory as soon as the method is `JIT`ed.

### Approach

#### Drag n Drop on dnSpy
Opening the file on `dnSpy`, we see that Hello class is almost empty, with only a call on the static constructor. This is what necrobit did to it.
![dnSpy1](../../assets/img/defeating-reactors-necrobit/dnSpy1.png)

That method has control-flow obfuscation applied to it so let's clean it first, so it's easier to read.

#### Cleaning the control-flow obfuscation
There is a really handy tool for this called [.NetReactorCfCleaner](https://github.com/SychicBoy/.NetReactorCfCleaner)
Note: After running it through this tool, the file doesn't run anymore, we just want to view it.

#### The hashtable
Now if we open the method that we found previously on the static constructor and scroll down a bit, we will indeed see info added into a hashtable.
![dnSpy2](../../assets/img/defeating-reactors-necrobit/dnSpy2.png)

If we use dnSpy's analyzer we see that this hashtable is also used on a method which seems to be the `JIT` `CompileMethod` hook
![dnSpy3](../../assets/img/defeating-reactors-necrobit/dnSpy3.png)

Now we have enough information, let's break it.

#### Retrieving the hashtable
Since we are doing this `dynamically` and not `statically`, all we need to do is load the assembly and locate the field, then get its value.

```csharp
var assembly = Assembly.LoadFrom("NecrobitTest.exe");

var type = assembly.GetTypes().First(d => d.Name == "nLvrU8AQJDKRRZAB7e");
var hashtableField = type.GetRuntimeFields().First(d => d.Name == "Nll0SVdCxp");

var hashtableValue = (Hashtable)hashtableField.GetValue(null);
```
We can now loop through it. The value of the entry is a struct used in the program, let's use reflection to get the `CIL` byte array.
```csharp
foreach (DictionaryEntry entry in hashtableValue)
{
    Console.WriteLine($"{entry.Key} -> {ExtractArray(entry.Value).Length}");
}
byte[] ExtractArray(object entry)
{
    foreach (var field in entry.GetType().GetRuntimeFields())
    {
        if (field.FieldType == typeof(byte[]))
        {
            return (byte[])field.GetValue(entry);
        }
    }
    return new byte[0];
}
```
```
85764037 -> 7
85729417 -> 19
85729460 -> 102
85729465 -> 12
85729393 -> 12
85729409 -> 7
85729425 -> 22
85764032 -> 129
85763989 -> 7
85764005 -> 12
0 -> 1

Process finished with exit code 0.
```
#### Key to method
We have a key -> cil byte array hashtable, now we need to find which method the key corresponds to.
On the screenshot that I showed earlier I mentioned that the key is Method `RVA` + `HInstance` of the module. Let's get the module `HInstance` from the assembly.
```csharp
var hInstance = Marshal.GetHINSTANCE(assembly.ManifestModule).ToInt64();
```
Now if we just subtract it we get the method `RVA`, but it seems to be +1 so let's subtract 1 from it.
```csharp
Console.WriteLine($"{(long)entry.Key - hInstance - 1:X} -> {ExtractArray(entry.Value).Length}");
```
```csharp
20B3 -> 102
20B8 -> 12
2070 -> 12
2080 -> 7
2090 -> 22
A7BF -> 129
A794 -> 7
A7A4 -> 12
A7C4 -> 7
2088 -> 19
FFFFFFFFFD99FFFF -> 1

Process finished with exit code 0.
```
![dnSpy4](../../assets/img/defeating-reactors-necrobit/dnSpy4.png)

Now let's use [AsmResolver](https://github.com/Washi1337/AsmResolver/) to get the actual method from `RVA`. We load in both the `PEImage` and the `ModuleDefinition` then we get the `TableStream` from the `DotNetDirectory` and then get the `MethodDefinitionRow` table. We then search for the row that has our `RVA` and we create a `MetadataToken` so we can look for the `MethodDefinition` in the `ModuleDefinition`
```csharp
var peImage = PEImage.FromFile("NecrobitTest.exe");
var module = ModuleDefinition.FromFile("NecrobitTest.exe");
var table = peImage.DotNetDirectory.Metadata.GetStream<TablesStream>().GetTable<MethodDefinitionRow>().ToList();
foreach (DictionaryEntry entry in hashtableValue)
{
    var cilBytes = ExtractArray(entry.Value);
    var rva = (long) entry.Key - hInstance - 1;
    var row = table.SingleOrDefault(d => d.Body.Rva == rva);
    var index = table.IndexOf(row) + 1;
    var token = new MetadataToken(row.TableIndex, (uint)index);
    if (module.TryLookupMember(token, out var m))
    {
        if (m is MethodDefinition methodDefinition)
        {
            Console.WriteLine(methodDefinition.Name);
        }
    }
}
```
```
.ctor
.ctor
get_Username
SayHello
.ctor
.ctor
.ctor
.ctor

Process finished with exit code 0.
```
Boom! We got the `methodDefinition` from the `RVA`!
#### Disassembling the cil byte array

`AsmResolver` has pretty handy tools for this.
```csharp
var operandResolver =
    new PhysicalCilOperandResolver(module,methodDefinition.CilMethodBody);
BinaryStreamReader reader = ByteArrayDataSource.CreateReader(cilBytes);
var disassembler = new CilDisassembler(in reader, operandResolver);
var instructions = disassembler.ReadInstructions();
foreach (var instruction in instructions)
{
    Console.WriteLine(instruction);
}
```
```
.ctor
IL_0000: call System.Void JOoSTcUQYrhd3hbI7F.iehh7boeaNq3xAaFC6::Hn9cnwCrR()
IL_0005: ldarg.0
IL_0006: call System.Void System.Object::.ctor()
IL_000B: ret
.ctor
IL_0000: call System.Void JOoSTcUQYrhd3hbI7F.iehh7boeaNq3xAaFC6::Hn9cnwCrR()
IL_0005: ldarg.0
IL_0006: call System.Void System.Object::.ctor()
IL_000B: ret
get_Username
IL_0000: ldarg.0
IL_0001: ldfld System.String NecrobitTest.Hello::<Username>k__BackingField
IL_0006: ret
SayHello
IL_0000: ldstr "Hello "
IL_0005: ldarg.0
IL_0006: call System.String NecrobitTest.Hello::get_Username()
IL_000B: call System.String System.String::Concat(System.String, System.String)
IL_0010: call System.Void System.Console::WriteLine(System.String)
IL_0015: ret
.ctor
IL_0000: ldarg.0
IL_0001: call System.Void System.Attribute::.ctor()
IL_0006: ret
.ctor
IL_0000: call System.Void JOoSTcUQYrhd3hbI7F.iehh7boeaNq3xAaFC6::Hn9cnwCrR()
IL_0005: ldarg.0
IL_0006: call System.Void System.Object::.ctor()
IL_000B: ret
.ctor
IL_0000: ldarg.0
IL_0001: call System.Void System.Object::.ctor()
IL_0006: ret
.ctor
IL_0000: call System.Void JOoSTcUQYrhd3hbI7F.iehh7boeaNq3xAaFC6::Hn9cnwCrR()
IL_0005: ldarg.0
IL_0006: call System.Void System.Object::.ctor()
IL_000B: ldarg.0
IL_000C: ldarg.1
IL_000D: stfld System.String NecrobitTest.Hello::<Username>k__BackingField
IL_0012: ret

Process finished with exit code 0.
```
There we go, these instructions look familiar :D. Only thing left is `recompiling` and `rebuilding` it.
#### Recompiling & Rebuilding
```csharp
foreach (DictionaryEntry entry in hashtableValue)
{
    var cilBytes = ExtractArray(entry.Value);
    var rva = (long) entry.Key - hInstance - 1;
    var row = table.SingleOrDefault(d => d.Body.Rva == rva);
    var index = table.IndexOf(row) + 1;
    var token = new MetadataToken(row.TableIndex, (uint) index);
    if (module.TryLookupMember(token, out var m))
    {
        if (m is MethodDefinition methodDefinition)
        {
            Console.WriteLine(methodDefinition.Name);
            var operandResolver =
                new PhysicalCilOperandResolver(module,methodDefinition.CilMethodBody);
            BinaryStreamReader reader = ByteArrayDataSource.CreateReader(cilBytes);
            var disassembler = new CilDisassembler(in reader, operandResolver);
            var instructions = disassembler.ReadInstructions();
            methodDefinition.CilMethodBody.Instructions.Clear();
            methodDefinition.CilMethodBody.Instructions.AddRange(instructions);
        }
    }
}
module.Write("NecrobitTest-UnNecrobit.exe");
```
#### Final Result

![dnSpy5](../../assets/img/defeating-reactors-necrobit/dnSpy5.png)

![dnSpy6](../../assets/img/defeating-reactors-necrobit/dnSpy6.png)

Goal has been achieved 👍 We could remove the junk but there's no need in this post.

#### Limitations
The hashtable only contains the instruction bytes but the local variables are missing too from the method, though this was not a problem for our sample.

### Credits

Thanks to Washi1337 for [AsmResolver](https://github.com/Washi1337/AsmResolver/)

Thanks to 0xd4d for [dnSpy](https://github.com/dnSpy/dnSpy)

Thanks to SychicBoy for [.NetReactorCfCleaner](https://github.com/SychicBoy/.NetReactorCfCleaner)

### Where can I find the code for this?

You can find the repo [Here](https://github.com/0xInception/NecrobitDumping)