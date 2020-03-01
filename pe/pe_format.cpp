#include "pe.h"
#include "pe.h"
#include "pe_constants.h"
#include "pe_header.h"
#include "pe_debug.h"
#include "dotnet/dotnet.h"
#include "borland/borland_version.h"
#include <redasm/support/utils.h>
#include <redasm/context.h>

template<size_t b> PEFormatT<b>::PEFormatT(PELoader *peloader): m_peloader(peloader), m_sectiontable(nullptr), m_datadirectory(nullptr)
{
    m_imagebase = m_sectionalignment = m_entrypoint = 0;
    m_classifier.setBits(b);

    m_validimportsections.insert(".text");
    m_validimportsections.insert(".idata");
    m_validimportsections.insert(".rdata");
}

template<size_t b> const DotNetReader *PEFormatT<b>::dotNetReader() const { return m_dotnetreader.get(); }
template<size_t b> address_t PEFormatT<b>::rvaToVa(address_t rva) const { return rva + m_imagebase; }
template<size_t b> address_t PEFormatT<b>::vaToRva(address_t va) const { return va - m_imagebase; }
template<size_t b> const PEClassifier *PEFormatT<b>::classifier() const { return &m_classifier; }

template<size_t b> void PEFormatT<b>::load()
{
    m_sectiontable = IMAGE_FIRST_SECTION(m_peloader->ntHeaders());

    if(b == 64)
        m_optionalheader = reinterpret_cast<const ImageOptionalHeader*>(&m_peloader->ntHeaders()->OptionalHeader64);
    else
        m_optionalheader = reinterpret_cast<const ImageOptionalHeader*>(&m_peloader->ntHeaders()->OptionalHeader32);

    m_imagebase = m_optionalheader->ImageBase;
    m_sectionalignment = m_optionalheader->SectionAlignment;
    m_entrypoint = m_imagebase + m_optionalheader->AddressOfEntryPoint;
    m_datadirectory = reinterpret_cast<const ImageDataDirectory*>(&m_optionalheader->DataDirectory);

    this->loadSections();
    ImageCorHeader* corheader = this->checkDotNet();

    if(m_classifier.checkDotNet() == PEClassification::DotNet_1)
        r_ctx->log(".NET 1.x is not supported");
    else if(!corheader)
        this->loadDefault();
    else
        this->loadDotNet(reinterpret_cast<ImageCor20Header*>(corheader));

    m_classifier.display();
}

template<size_t b> void PEFormatT<b>::checkResources()
{
    const ImageDataDirectory& resourcedatadir = m_datadirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];

    if(!resourcedatadir.VirtualAddress)
        return;

    ImageResourceDirectory* resourcedir = m_peloader->rvaPointer<ImageResourceDirectory>(resourcedatadir.VirtualAddress);

    if(!resourcedir)
        return;

    PEResources peresources(resourcedir);
    m_classifier.classifyDelphi(m_peloader->dosHeader(), m_peloader->ntHeaders(), resourcedir);
}

template<size_t b> void PEFormatT<b>::checkDebugInfo()
{
    const ImageDataDirectory& debuginfodir = m_datadirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];

    if(!debuginfodir.VirtualAddress)
        return;

    ImageDebugDirectory* debugdir = m_peloader->rvaPointer<ImageDebugDirectory>(debuginfodir.VirtualAddress);

    if(!debugdir)
        return;

    u64 dbgoffset = 0;

    if(debugdir->AddressOfRawData)
    {
        offset_location offset = PEUtils::rvaToOffset(m_peloader->ntHeaders(), m_imagebase - debugdir->AddressOfRawData);

        if(offset.valid)
            dbgoffset = offset;
    }

    if(!dbgoffset && debugdir->PointerToRawData)
        dbgoffset = debugdir->PointerToRawData;

    if(debugdir->Type == IMAGE_DEBUG_TYPE_UNKNOWN)
        r_ctx->log("Debug info type: UNKNOWN");
    else if(debugdir->Type == IMAGE_DEBUG_TYPE_COFF)
        r_ctx->log("Debug info type: COFF");
    else if(debugdir->Type == IMAGE_DEBUG_TYPE_CODEVIEW)
    {
        r_ctx->log("Debug info type: CodeView");
        m_classifier.classifyVisualStudio();

        if(!m_peloader->view().inRange(dbgoffset))
            return;

        CVHeader* cvhdr = m_peloader->pointer<CVHeader>(dbgoffset);

        if(cvhdr->Signature == PE_PDB_NB10_SIGNATURE)
        {
            CvInfoPDB20* pdb20 = m_peloader->pointer<CvInfoPDB20>(dbgoffset);
            r_ctx->log("PDB 2.0 @ " + String(pdb20->PdbFileName).quoted());
        }
        else if(cvhdr->Signature == PE_PDB_RSDS_SIGNATURE)
        {
            CvInfoPDB70* pdb70 = m_peloader->pointer<CvInfoPDB70>(dbgoffset);
            r_ctx->log("PDB 7.0 @ " + String(pdb70->PdbFileName).quoted());
        }
        else
            r_ctx->log("Unknown Signature: '" + String(reinterpret_cast<const char*>(&cvhdr->Signature), sizeof(u32)).quoted());
    }
    else if(debugdir->Type == IMAGE_DEBUG_TYPE_FPO)
        r_ctx->log("Debug info type: FPO");
    else if(debugdir->Type == IMAGE_DEBUG_TYPE_MISC)
        r_ctx->log("Debug info type: Misc");
    else if(debugdir->Type == IMAGE_DEBUG_TYPE_EXCEPTION)
        r_ctx->log("Debug info type: Exception");
    else if(debugdir->Type == IMAGE_DEBUG_TYPE_FIXUP)
        r_ctx->log("Debug info type: FixUp");
    else if(debugdir->Type == IMAGE_DEBUG_TYPE_OMAP_TO_SRC)
        r_ctx->log("Debug info type: OMAP to Src");
    else if(debugdir->Type == IMAGE_DEBUG_TYPE_OMAP_FROM_SRC)
        r_ctx->log("Debug info type: OMAP from Src");
    else if(debugdir->Type == IMAGE_DEBUG_TYPE_BORLAND)
        r_ctx->log("Debug info type: Borland");
    else if(debugdir->Type == IMAGE_DEBUG_TYPE_RESERVED10)
        r_ctx->log("Debug info type: Reserved10");
    else if(debugdir->Type == IMAGE_DEBUG_TYPE_CLSID)
        r_ctx->log("Debug info type: CLSID");
    else if(debugdir->Type == IMAGE_DEBUG_TYPE_VC_FEATURE)
        r_ctx->log("Debug info type: VC Feature");
    else if(debugdir->Type == IMAGE_DEBUG_TYPE_POGO)
        r_ctx->log("Debug info type: POGO");
    else if(debugdir->Type == IMAGE_DEBUG_TYPE_ILTCG)
        r_ctx->log("Debug info type: ILTCG");
    else if(debugdir->Type == IMAGE_DEBUG_TYPE_REPRO)
        r_ctx->log("Debug info type: REPRO");
    else
        r_ctx->log("Unknown Debug info type (value " + String::hex(debugdir->Type, 32, true) + ")");
}

template<size_t b> ImageCorHeader* PEFormatT<b>::checkDotNet()
{
    const ImageDataDirectory& dotnetdir = m_datadirectory[IMAGE_DIRECTORY_ENTRY_DOTNET];

    if(!dotnetdir.VirtualAddress)
        return nullptr;

    ImageCorHeader* corheader = m_peloader->rvaPointer<ImageCorHeader>(dotnetdir.VirtualAddress);
    m_classifier.classifyDotNet(corheader);
    return corheader;
}

template<size_t b> void PEFormatT<b>::loadDotNet(ImageCor20Header* corheader)
{
    if(!corheader->MetaData.VirtualAddress)
    {
        r_ctx->log("Invalid .NET MetaData");
        return;
    }

    ImageCor20MetaData* cormetadata = m_peloader->rvaPointer<ImageCor20MetaData>(corheader->MetaData.VirtualAddress);

    if(!cormetadata)
        return;

    m_dotnetreader = std::make_unique<DotNetReader>(cormetadata);

    if(!m_dotnetreader->isValid())
        return;

    m_dotnetreader->iterateTypes([&](u32 rva, const String& name) {
        ldrdoc_r(m_peloader)->function(m_imagebase + rva, name);
    });
}

template<size_t b> void PEFormatT<b>::loadDefault()
{
    this->loadExports();

    if(!this->loadImports())
        r_ctx->log("WARNING: This file seems to be PACKED");

    this->loadTLS();
    this->loadConfig();
    this->loadExceptions();
    this->loadSymbolTable();
    this->checkDebugInfo();
    this->checkResources();

    ldrdoc_r(m_peloader)->entry(m_entrypoint);
    m_classifier.classify(m_peloader->ntHeaders());

    for(const auto& sig : m_classifier.signatures())
        m_peloader->signature(sig);
}

template<size_t b> void PEFormatT<b>::loadSections()
{
    for(size_t i = 0; i < m_peloader->ntHeaders()->FileHeader.NumberOfSections; i++)
    {
        const ImageSectionHeader& section = m_sectiontable[i];
        type_t flags = SegmentType::None;

        if((section.Characteristics & IMAGE_SCN_CNT_CODE) || (section.Characteristics & IMAGE_SCN_MEM_EXECUTE))
            flags |= SegmentType::Code;

        if((section.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) || (section.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA))
            flags |= SegmentType::Data;

        u64 vsize = section.Misc.VirtualSize;

        if(!section.SizeOfRawData)
            flags |= SegmentType::Bss;

        u64 diff = vsize % m_sectionalignment;

        if(diff)
            vsize += m_sectionalignment - diff;

        String name = PEUtils::sectionName(reinterpret_cast<const char*>(section.Name));

        if(name.empty()) // Rename unnamed sections
            name = "sect" + String::number(i);

        ldrdoc_r(m_peloader)->segment(name, section.PointerToRawData, m_imagebase + section.VirtualAddress, section.SizeOfRawData, vsize, flags);
    }

    Segment* segment = m_peloader->documentNew()->segment(m_entrypoint);

    if(segment) // Entry points always points to code segment
        segment->type |= SegmentType::Code;
}

template<size_t b> void PEFormatT<b>::loadExports()
{
    const ImageDataDirectory& exportdir = m_datadirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if(!exportdir.VirtualAddress)
        return;

    ImageExportDirectory* exporttable = m_peloader->rvaPointer<ImageExportDirectory>(exportdir.VirtualAddress);

    if(!exporttable)
        return;

    u32* functions = m_peloader->rvaPointer<u32>(exporttable->AddressOfFunctions);
    u32* names = m_peloader->rvaPointer<u32>(exporttable->AddressOfNames);
    u16* nameords = m_peloader->rvaPointer<u16>(exporttable->AddressOfNameOrdinals);

    if(!functions || !names || !nameords)
    {
        r_ctx->log("Corrupted export table");
        return;
    }

    for(size_t i = 0; i < exporttable->NumberOfFunctions; i++)
    {
        if(!functions[i]) continue;

        bool namedfunction = false;
        u64 funcep = m_imagebase + functions[i];
        const Segment* segment = ldrdoc_r(m_peloader)->segment(funcep);
        if(!segment) continue;

        bool isfunction = segment->is(SegmentType::Code);

        for(pe_integer_t j = 0; j < exporttable->NumberOfNames; j++)
        {
            if(nameords[j] != i) continue;
            namedfunction = true;

            if(isfunction) ldrdoc_r(m_peloader)->exportedFunction(funcep, m_peloader->rvaPointer<const char>(names[j]));
            else ldrdoc_r(m_peloader)->exported(funcep, m_peloader->rvaPointer<const char>(names[j]));
            break;
        }

        if(namedfunction) continue;
        if(isfunction) ldrdoc_r(m_peloader)->exportedFunction(funcep, Ordinals::ordinal(exporttable->Base + 1));
        else ldrdoc_r(m_peloader)->exported(funcep, Ordinals::ordinal(exporttable->Base + 1));
    }
}

template<size_t b> bool PEFormatT<b>::loadImports()
{
    const ImageDataDirectory& importdir = m_datadirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if(!importdir.VirtualAddress) return false;

    ImageImportDescriptor* importtable = m_peloader->rvaPointer<ImageImportDescriptor>(importdir.VirtualAddress);
    if(!importtable) return false;

    for(size_t i = 0; i < importtable[i].FirstThunk; i++)
        this->readDescriptor(importtable[i], b == 64 ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32);

    Segment* segment = ldrdoc_r(m_peloader)->segment(m_imagebase + importdir.VirtualAddress);
    return segment && (m_validimportsections.find(segment->name()) != m_validimportsections.end());
}

template<size_t b> void PEFormatT<b>::loadExceptions()
{
    const ImageDataDirectory& exceptiondir = m_datadirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if(!exceptiondir.VirtualAddress || !exceptiondir.Size) return;

    ImageRuntimeFunctionEntry* runtimeentry = m_peloader->rvaPointer<ImageRuntimeFunctionEntry>(exceptiondir.VirtualAddress);
    if(!runtimeentry) return;

    u64 c = 0, csize = 0;

    for(pe_integer_t i = 0; csize < exceptiondir.Size; i++, csize += sizeof(ImageRuntimeFunctionEntry))
    {
        address_t va = m_imagebase + runtimeentry[i].BeginAddress;
        if(!ldrdoc_r(m_peloader)->segment(va) || (runtimeentry[i].UnwindInfoAddress & 1)) continue;

        UnwindInfo* unwindinfo = m_peloader->rvaPointer<UnwindInfo>(runtimeentry[i].UnwindInfoAddress & ~1u);
        if(!unwindinfo || (unwindinfo->Flags & UNW_FLAG_CHAININFO)) continue;

        ldrdoc_r(m_peloader)->function(va);
        c++;
    }

    if(c) r_ctx->log("Found " + String::number(c) + " function(s) in Exception Directory");
}

template<size_t b> void PEFormatT<b>::loadConfig()
{
    const ImageDataDirectory& configdir = m_datadirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    if(!configdir.VirtualAddress) return;

    ImageLoadConfigDirectory* loadconfigdir = m_peloader->rvaPointer<ImageLoadConfigDirectory>(configdir.VirtualAddress);
    if(!loadconfigdir || !loadconfigdir->SecurityCookie) return;

    ldrdoc_r(m_peloader)->data(loadconfigdir->SecurityCookie, b, PE_SECURITY_COOKIE_SYMBOL);
}

template<size_t b> void PEFormatT<b>::loadTLS()
{
    const ImageDataDirectory& tlsdir = m_datadirectory[IMAGE_DIRECTORY_ENTRY_TLS];

    if(!tlsdir.VirtualAddress)
        return;

    ImageTlsDirectory* imagetlsdir = m_peloader->rvaPointer<ImageTlsDirectory>(tlsdir.VirtualAddress);

    if(imagetlsdir)
        this->readTLSCallbacks(imagetlsdir);
}

template<size_t b> void PEFormatT<b>::loadSymbolTable()
{
    if(!m_peloader->ntHeaders()->FileHeader.PointerToSymbolTable || !m_peloader->ntHeaders()->FileHeader.NumberOfSymbols)
        return;

    r_ctx->log("Loading symbol table @ " + String::hex(m_peloader->ntHeaders()->FileHeader.PointerToSymbolTable));

    r_pm->execute("coff", { m_peloader->pointer<u8>(m_peloader->ntHeaders()->FileHeader.PointerToSymbolTable),
                            m_peloader->ntHeaders()->FileHeader.NumberOfSymbols });
}

template<size_t b> void PEFormatT<b>::readTLSCallbacks(const ImageTlsDirectory *tlsdirectory)
{
    if(!tlsdirectory->AddressOfCallBacks)
        return;

    pe_integer_t* callbacks = m_peloader->addrpointer<pe_integer_t>(tlsdirectory->AddressOfCallBacks);

    for(pe_integer_t i = 0; *callbacks; i++, callbacks++)
        ldrdoc_r(m_peloader)->function(*callbacks, "TlsCallback_" + String::number(i));
}

template<size_t b> void PEFormatT<b>::readDescriptor(const ImageImportDescriptor& importdescriptor, pe_integer_t ordinalflag)
{
    // Check if OFT exists
    ImageThunkData* thunk = m_peloader->rvaPointer<ImageThunkData>(importdescriptor.OriginalFirstThunk ? importdescriptor.OriginalFirstThunk : importdescriptor.FirstThunk);
    if(!thunk) return;

    String descriptorname = String(m_peloader->rvaPointer<const char>(importdescriptor.Name)).toLower();
    m_classifier.classifyImport(descriptorname);

    for(size_t i = 0; thunk[i]; i++)
    {
        String importname;
        address_t address = m_imagebase + (importdescriptor.FirstThunk + (i * sizeof(ImageThunkData))); // Instructions refers to FT

        if(!(thunk[i] & ordinalflag))
        {
            ImageImportByName* importbyname = m_peloader->rvaPointer<ImageImportByName>(thunk[i]);
            if(!importbyname) continue;

            importname = PEUtils::importName(descriptorname, reinterpret_cast<const char*>(&importbyname->Name));
        }
        else
        {
            u16 ordinal = static_cast<u16>(ordinalflag ^ thunk[i]);

            if(!PEImports::importName<b>(descriptorname, ordinal, importname)) importname = PEUtils::importName(descriptorname, ordinal);
            else importname = PEUtils::importName(descriptorname, importname);
        }

        ldrdoc_r(m_peloader)->imported(address, REDasm::bytes_val_count<b>::value, importname);
    }
}

template class PEFormatT<32>;
template class PEFormatT<64>;
