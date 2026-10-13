// SPDX-License-Identifier: MIT
// Research implementation. See README.md and docs/IMPLEMENTATION.md.
#include <pbc.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <map>
#include <numeric>
#include <optional>
#include <random>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

// Stable OpenSSL libcrypto SHA256 ABI; also works on a runtime-only installation.
extern "C" unsigned char* SHA256(const unsigned char*, size_t, unsigned char*);
using Bytes = std::vector<unsigned char>;
using Attrs = std::set<int>;
static void require(bool ok, const std::string& message) {
    if (!ok) throw std::runtime_error(message);
}
struct Context {
    pairing_t p;
    explicit Context(const std::string& path) {
        std::ifstream in(path, std::ios::binary);
        require(bool(in), "Cannot open pairing parameters: " + path);
        std::string data((std::istreambuf_iterator<char>(in)), {});
        require(!data.empty() && pairing_init_set_buf(p, data.data(), data.size()) == 0,
                "Invalid pairing parameters");
        if (!pairing_is_symmetric(p)) { pairing_clear(p); throw std::runtime_error("Symmetric pairing required"); }
    }
    ~Context() { pairing_clear(p); }
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
};
enum class Kind { Scalar, G, GT };
class E {
    element_t value;
    void init() {
        if (kind == Kind::Scalar) element_init_Zr(value, ctx->p);
        else if (kind == Kind::G) element_init_G1(value, ctx->p);
        else element_init_GT(value, ctx->p);
    }
public:
    Context* ctx;
    Kind kind;
    E(Context& c, Kind k) : ctx(&c), kind(k) { init(); if(k == Kind::Scalar) element_set0(value); else element_set1(value); }
    E(const E& other) : ctx(other.ctx), kind(other.kind) { init(); element_set(value, other.raw()); }
    E(E&& other) : E(static_cast<const E&>(other)) {}
    E& operator=(const E& other) {
        if (this != &other) {
            require(ctx == other.ctx && kind == other.kind, "Element assignment type mismatch");
            element_set(value, other.raw());
        }
        return *this;
    }
    ~E() { element_clear(value); }
    element_ptr raw() const { return const_cast<element_ptr>(&value[0]); }
    bool zero() const { return element_is0(raw()) != 0; }
    bool one() const { return element_is1(raw()) != 0; }
    Bytes bytes() const {
        Bytes out(element_length_in_bytes(raw())); element_to_bytes(out.data(), raw()); return out;
    }
};
static E scalar(Context& c, long v) { E r(c,Kind::Scalar); element_set_si(r.raw(),v); return r; }
static E randomElement(Context& c, Kind k) {
    E r(c,k); do { element_random(r.raw()); } while(k == Kind::Scalar ? r.zero() : r.one()); return r;
}
static void compatible(const E& a,const E& b) { require(a.ctx==b.ctx && a.kind==b.kind,"Element type mismatch"); }
static E operator*(const E& a,const E& b) { compatible(a,b); E r(*a.ctx,a.kind); element_mul(r.raw(),a.raw(),b.raw()); return r; }
static E operator/(const E& a,const E& b) {
    compatible(a,b); require(b.kind!=Kind::Scalar || !b.zero(),"Division by zero");
    E r(*a.ctx,a.kind); element_div(r.raw(),a.raw(),b.raw()); return r;
}
static E operator+(const E& a,const E& b) { compatible(a,b); require(a.kind==Kind::Scalar,"Scalar addition required"); E r(*a.ctx,a.kind); element_add(r.raw(),a.raw(),b.raw()); return r; }
static E operator-(const E& a,const E& b) { compatible(a,b); require(a.kind==Kind::Scalar,"Scalar subtraction required"); E r(*a.ctx,a.kind); element_sub(r.raw(),a.raw(),b.raw()); return r; }
static E neg(const E& a) { return scalar(*a.ctx,0)-a; }
static E power(const E& a,const E& z) { require(a.ctx==z.ctx && z.kind==Kind::Scalar,"Invalid exponent"); E r(*a.ctx,a.kind); element_pow_zn(r.raw(),a.raw(),z.raw()); return r; }
static E pair(const E& a,const E& b) { compatible(a,b); require(a.kind==Kind::G,"G pairing required"); E r(*a.ctx,Kind::GT); element_pairing(r.raw(),a.raw(),b.raw()); return r; }
static bool operator==(const E& a,const E& b) { compatible(a,b); return element_cmp(a.raw(),b.raw())==0; }
static bool operator!=(const E& a,const E& b) { return !(a==b); }
static void append(Bytes& a,const Bytes& b) { a.insert(a.end(),b.begin(),b.end()); }
static void u64(Bytes& b,uint64_t n) { for(int i=7;i>=0;--i) b.push_back(static_cast<unsigned char>(n>>(8*i))); }
static Bytes textBytes(const std::string& s) { return Bytes(s.begin(),s.end()); }
static Bytes digest(const Bytes& b) {
    Bytes out(32); require(SHA256(b.data(),b.size(),out.data())!=nullptr,"SHA256 failure"); return out;
}
static Bytes frame(const std::string& domain,const Bytes& bytes) {
    Bytes out=textBytes(domain); out.push_back(0); u64(out,bytes.size()); append(out,bytes); return out;
}
static E hashElement(Context& c,Kind k,const std::string& domain,const Bytes& data) {
    Bytes d=digest(frame(domain,data)); E out(c,k); element_from_hash(out.raw(),d.data(),d.size()); return out;
}
static E h1(const E& rid) { return hashElement(*rid.ctx,Kind::Scalar,"PRABKS-H1",rid.bytes()); }
static E h2(Context& c,const std::string& kw) { return hashElement(c,Kind::G,"PRABKS-H2",textBytes(kw)); }
static Bytes mask(const E& z,size_t length) {
    Bytes out,seed=frame("PRABKS-H",z.bytes()); u64(seed,length);
    for(uint64_t counter=0;out.size()<length;++counter) {
        Bytes input=seed; u64(input,counter); append(out,digest(input));
    }
    out.resize(length); return out;
}
static Bytes xorBytes(Bytes a,const Bytes& b) {
    require(a.size()==b.size(),"XOR length mismatch");
    for(size_t i=0;i<a.size();++i) a[i]^=b[i];
    return a;
}
// Big-endian injective encoding for the declared domain integer(message) < r.
// C1 retains leading zero bytes and length; no modular reduction of a message.
static E messageScalar(Context& c,const Bytes& data) {
    mpz_t x; mpz_init(x); mpz_import(x,data.size(),1,1,1,0,data.data());
    bool valid=mpz_cmp(x,c.p->r)<0;
    E out(c,Kind::Scalar); if(valid) element_set_mpz(out.raw(),x); mpz_clear(x);
    require(valid,"Message integer must be smaller than the scalar order"); return out;
}
static std::optional<E> decodeScalar(Context& c,const Bytes& data) {
    E out(c,Kind::Scalar); if(data.size()!=out.bytes().size()) return std::nullopt;
    element_from_bytes(out.raw(),const_cast<unsigned char*>(data.data()));
    if(out.bytes()!=data) return std::nullopt;
    return out;
}
static std::vector<E> powers(const E& tag,size_t eta) {
    std::vector<E> out; out.push_back(scalar(*tag.ctx,1));
    for(size_t k=1;k<eta;++k) out.push_back(out.back()*tag);
    return out;
}
static bool contains(const std::vector<E>& tags,const E& t) {
    return std::any_of(tags.begin(),tags.end(),[&](const E& v){return v==t;});
}
static std::vector<E> polynomial(Context& c,const std::vector<E>& tags,size_t eta) {
    require(eta>0 && tags.size()<eta,"Tag count must be <= eta-1");
    std::vector<E> result{scalar(c,1)},seen;
    for(const auto& tag:tags) {
        require(!contains(seen,tag),"Duplicate ciphertext tag"); seen.push_back(tag);
        std::vector<E> next(result.size()+1,scalar(c,0));
        for(size_t k=0;k<result.size();++k) { next[k]=next[k]-result[k]*tag; next[k+1]=next[k+1]+result[k]; }
        result=std::move(next);
    }
    result.resize(eta,scalar(c,0)); return result;
}
static E dot(const std::vector<E>& a,const std::vector<E>& b) {
    require(!a.empty() && a.size()==b.size(),"Dot-product dimension mismatch"); E out=scalar(*a[0].ctx,0);
    for(size_t k=0;k<a.size();++k) out=out+a[k]*b[k];
    return out;
}
static E productPowers(const std::vector<E>& bases,const std::vector<E>& exponents) {
    require(!bases.empty() && bases.size()==exponents.size(),"Group-product dimension mismatch");
    E out(*bases[0].ctx,bases[0].kind);
    for(size_t k=0;k<bases.size();++k) out=out*power(bases[k],exponents[k]);
    return out;
}

struct Policy {
    std::vector<std::vector<long>> matrix;
    std::vector<int> rho;
    void validate(int universe) const {
        require(!matrix.empty() && matrix.size()==rho.size() && !matrix[0].empty(),"Invalid policy shape");
        for(size_t i=0;i<matrix.size();++i) require(matrix[i].size()==matrix[0].size() && rho[i]>=0 && rho[i]<universe,"Invalid policy row");
    }
    static Policy all(int n) {
        require(n>0,"Empty AND policy"); Policy p;
        p.matrix.assign(n,std::vector<long>(n,0));
        for(int i=0;i<n;++i) { p.rho.push_back(i); p.matrix[i][i]=(i==0?1:-1); if(i+1<n) p.matrix[i][i+1]=1; }
        return p;
    }
};
static std::vector<E> shares(Context& c,const Policy& policy,const E& secret) {
    std::vector<E> v{secret},out;
    for(size_t j=1;j<policy.matrix[0].size();++j) v.push_back(randomElement(c,Kind::Scalar));
    for(const auto& row:policy.matrix) {
        E value=scalar(c,0); for(size_t j=0;j<row.size();++j) value=value+scalar(c,row[j])*v[j]; out.push_back(value);
    }
    return out;
}
using Reconstruction=std::vector<std::pair<size_t,E>>;
// Solve M_I^T * omega = (1,0,...,0), using public matrix and attributes only.
static std::optional<Reconstruction> reconstruct(Context& c,const Policy& policy,const Attrs& attrs) {
    std::vector<size_t> selected;
    for(size_t i=0;i<policy.rho.size();++i) if(attrs.count(policy.rho[i])) selected.push_back(i);
    if(selected.empty()) return std::nullopt;
    size_t m=policy.matrix[0].size(),n=selected.size();
    std::vector<std::vector<E>> a(m,std::vector<E>(n+1,scalar(c,0)));
    for(size_t r=0;r<m;++r) {
        for(size_t col=0;col<n;++col) a[r][col]=scalar(c,policy.matrix[selected[col]][r]);
        a[r][n]=scalar(c,r==0?1:0);
    }
    std::vector<size_t> pivots; size_t row=0;
    for(size_t col=0;col<n && row<m;++col) {
        size_t pivot=row; while(pivot<m && a[pivot][col].zero()) ++pivot;
        if(pivot==m) continue;
        std::swap(a[pivot],a[row]);
        E div=a[row][col]; for(size_t j=0;j<=n;++j) a[row][j]=a[row][j]/div;
        for(size_t r=0;r<m;++r) if(r!=row) {
            E factor=a[r][col]; for(size_t j=0;j<=n;++j) a[r][j]=a[r][j]-factor*a[row][j];
        }
        pivots.push_back(col); ++row;
    }
    for(size_t r=row;r<m;++r) if(!a[r][n].zero()) return std::nullopt;
    std::vector<E> omega(n,scalar(c,0));
    for(size_t r=0;r<pivots.size();++r) omega[pivots[r]]=a[r][n];
    Reconstruction out;
    for(size_t col=0;col<n;++col) if(!omega[col].zero()) out.emplace_back(selected[col],omega[col]);
    return out;
}

// Shared PR-ABE / PR-ABKS puncturable encryption core.
struct PSetup {
    E g,h,R,Gamma,Z,td;
    std::vector<E> B,c,hi,A,F,Ei;
    std::vector<std::vector<E>> U;
    std::vector<std::vector<std::vector<E>>> W; // W[first user][second user][attribute]
    int n,universe,eta;
    PSetup(Context& ctx,int users,int attrs,int dimension)
        :g(randomElement(ctx,Kind::G)),h(ctx,Kind::G),R(ctx,Kind::G),Gamma(ctx,Kind::G),Z(ctx,Kind::GT),td(randomElement(ctx,Kind::Scalar)),n(users),universe(attrs),eta(dimension) {
        require(n>=2 && universe>0 && eta>0,"Invalid setup sizes");
        E alpha=randomElement(ctx,Kind::Scalar),beta=randomElement(ctx,Kind::Scalar);
        E gamma=randomElement(ctx,Kind::Scalar),theta=randomElement(ctx,Kind::Scalar);
        h=power(g,beta); R=power(g,gamma); Gamma=power(g,theta); Z=power(pair(g,g),alpha);
        for(int k=0;k<eta;++k) B.push_back(power(g,randomElement(ctx,Kind::Scalar)));
        E Rd=power(productPowers(B,powers(td,eta)),gamma);
        std::vector<E> t,D;
        for(int i=0;i<n;++i) {
            E ci=randomElement(ctx,Kind::Scalar); while((theta+ci).zero()) ci=randomElement(ctx,Kind::Scalar);
            c.push_back(ci); D.push_back(theta+ci); t.push_back(randomElement(ctx,Kind::Scalar));
            hi.push_back(power(g,t.back()));
            A.push_back(power(g,alpha/D.back())*power(h,gamma/D.back()+t.back()));
            Ei.push_back(power(Rd,scalar(ctx,1)/D.back())); F.push_back(power(Gamma,t.back()));
        }
        std::vector<std::vector<E>> u(n,std::vector<E>(universe,scalar(ctx,0)));
        U.assign(n,std::vector<E>(universe,E(ctx,Kind::G)));
        W.assign(n,std::vector<std::vector<E>>(n,std::vector<E>(universe,E(ctx,Kind::G))));
        for(int i=0;i<n;++i) for(int w=0;w<universe;++w) {
            u[i][w]=randomElement(ctx,Kind::Scalar); U[i][w]=power(g,u[i][w]);
        }
        for(int i=0;i<n;++i) for(int j=0;j<n;++j) if(i!=j)
            for(int w=0;w<universe;++w) W[i][j][w]=power(hi[i],u[j][w]*D[i]);
    }
};
struct Piece { E a,b,c; };
struct PKey { Piece base; std::vector<Piece> pieces; std::vector<E> tags; };
struct Registration { E pk; std::vector<E> cross; };
struct PUser { Registration registration; PKey key; };
static PUser keygen(const PSetup& s,int i) {
    Context& c=*s.g.ctx; E d=randomElement(c,Kind::Scalar),v=randomElement(c,Kind::Scalar);
    std::vector<E> cross(s.n,E(c,Kind::G));
    for(int j=0;j<s.n;++j) if(i!=j) cross[j]=power(s.hi[j],d);
    return {{power(s.g,d),cross},{{power(s.hi[i],d)*s.A[i]*power(s.h,v),
        s.Ei[i]*power(productPowers(s.B,powers(s.td,s.eta)),v),
        s.R*power(s.Gamma*power(s.g,s.c[i]),v)}, {}, {}}};
}
struct PPub { E g,h,Gamma,Z,td,T; std::vector<E> B,U; };
struct PToken { E c,hi,F,xi; std::vector<E> W; Attrs attrs; };
struct PRegistered { PPub pub; std::vector<PToken> tokens; };
static PRegistered registration(const PSetup& s,const std::vector<Registration>& users,const std::vector<Attrs>& attrs) {
    Context& c=*s.g.ctx;
    require(users.size()==size_t(s.n) && attrs.size()==users.size(),"Registration size mismatch");
    E T(c,Kind::G); std::vector<E> U(s.universe,E(c,Kind::G)); std::vector<PToken> tokens;
    for(int i=0;i<s.n;++i) {
        require(users[i].cross.size()==size_t(s.n),"Cross-term size mismatch");
        for(int j=0;j<s.n;++j) if(i!=j)
            require(pair(s.g,users[i].cross[j])==pair(users[i].pk,s.hi[j]),"Invalid registration cross term");
        for(int w:attrs[i]) require(w>=0 && w<s.universe,"Invalid registered attribute");
        T=T*users[i].pk;
    }
    for(int w=0;w<s.universe;++w) for(int j=0;j<s.n;++j) if(!attrs[j].count(w)) U[w]=U[w]*s.U[j][w];
    for(int i=0;i<s.n;++i) {
        E xi(c,Kind::G); std::vector<E> W(s.universe,E(c,Kind::G));
        for(int j=0;j<s.n;++j) if(i!=j) {
            xi=xi*users[j].cross[i];
            for(int w=0;w<s.universe;++w) if(!attrs[j].count(w)) W[w]=W[w]*s.W[i][j][w];
        }
        tokens.push_back({s.c[i],s.hi[i],s.F[i],xi,W,attrs[i]});
    }
    return {{s.g,s.h,s.Gamma,s.Z,s.td,T,s.B,U},tokens};
}
struct PCipher { Policy policy; std::vector<E> tags; Bytes C1; E C2,C4,C6,C7; std::vector<E> C3,C5; };
static PCipher encrypt(const PPub& p,const Policy& policy,const Bytes& message,const std::vector<E>& tags) {
    Context& c=*p.g.ctx; policy.validate(p.U.size());
    require(!contains(tags,p.td),"Distinguished tag cannot be a ciphertext tag");
    auto theta=polynomial(c,tags,p.B.size()); E mu=messageScalar(c,message);
    E s=randomElement(c,Kind::Scalar),sp=randomElement(c,Kind::Scalar);
    E hx=randomElement(c,Kind::G),hy=hx/p.h; auto phi=shares(c,policy,s);
    std::vector<E> C3,C5;
    for(size_t i=0;i<phi.size();++i) C3.push_back(power(hx,phi[i])/power(p.U[policy.rho[i]],s));
    for(size_t k=0;k<p.B.size();++k) C5.push_back(power(power(p.h,theta[k])*p.B[k],s));
    Bytes payload=message; append(payload,sp.bytes());
    return {policy,tags,xorBytes(payload,mask(power(p.Z,s),payload.size())),power(p.g,s),
        power(hy,s)/power(p.T,s),power(p.Gamma,s),power(p.g,mu)*power(p.Gamma,sp),C3,C5};
}
static PKey puncture(const PPub& p,const E& ci,const PKey& previous,const E& tag) {
    if(contains(previous.tags,tag)) return previous;
    Context& c=*p.g.ctx; PKey updated=previous;
    E varpi=randomElement(c,Kind::Scalar),phi=randomElement(c,Kind::Scalar),phip=randomElement(c,Kind::Scalar);
    updated.base.a=previous.base.a*power(p.g,neg(varpi))*power(p.h,phi);
    updated.base.b=previous.base.b*power(productPowers(p.B,powers(p.td,p.B.size())),phi);
    E gD=p.Gamma*power(p.g,ci);
    updated.base.c=previous.base.c*power(gD,phi);
    updated.pieces.push_back({power(p.g,varpi)*power(p.h,phip),
        power(productPowers(p.B,powers(tag,p.B.size())),phip),power(gD,phip)});
    updated.tags.push_back(tag); return updated;
}
static std::optional<E> partialDecrypt(const PPub& p,const PToken& token,const PCipher& ct) {
    Context& c=*p.g.ctx; ct.policy.validate(p.U.size());
    if(ct.C3.size()!=ct.policy.rho.size() || ct.C5.size()!=p.B.size()) return std::nullopt;
    auto weights=reconstruct(c,ct.policy,token.attrs); if(!weights) return std::nullopt;
    E hciFi=power(token.hi,token.c)*token.F;
    E numerator=pair(power(ct.C2,token.c)*ct.C6,token.xi)*pair(ct.C4,hciFi);
    E denominator(c,Kind::GT);
    for(const auto& item:*weights) {
        size_t row=item.first; int attr=ct.policy.rho[row];
        denominator=denominator*power(pair(ct.C3[row],hciFi)*pair(ct.C2,token.W[attr]),item.second);
    }
    return numerator/denominator;
}
static std::optional<Bytes> finishDecrypt(const PPub& p,const E& ci,const PKey& key,const PCipher& ct,const E& delta) {
    Context& c=*p.g.ctx;
    if(key.tags.size()!=key.pieces.size() || ct.C5.size()!=p.B.size()) return std::nullopt;
    for(const auto& t:key.tags) if(contains(ct.tags,t)) return std::nullopt;
    auto theta=polynomial(c,ct.tags,p.B.size()); E gDs=power(ct.C2,ci)*ct.C6;
    auto component=[&](const Piece& sk,const E& tag)->std::optional<E> {
        auto x=powers(tag,p.B.size()); E chi=dot(x,theta); if(chi.zero()) return std::nullopt;
        E inv=scalar(c,1)/chi;
        return pair(gDs,sk.a*power(sk.b,inv))*pair(productPowers(ct.C5,x),power(sk.c,neg(inv)));
    };
    auto base=component(key.base,p.td); if(!base) return std::nullopt; E z=delta * *base;
    for(size_t i=0;i<key.pieces.size();++i) { auto zu=component(key.pieces[i],key.tags[i]); if(!zu) return std::nullopt; z=z * *zu; }
    size_t width=scalar(c,0).bytes().size(); if(ct.C1.size()<width) return std::nullopt;
    Bytes payload=xorBytes(ct.C1,mask(z,ct.C1.size()));
    Bytes message(payload.begin(),payload.end()-width),spbytes(payload.end()-width,payload.end());
    auto sp=decodeScalar(c,spbytes); if(!sp) return std::nullopt;
    try { if(power(p.g,messageScalar(c,message))*power(p.Gamma,*sp)!=ct.C7) return std::nullopt; }
    catch(const std::runtime_error&) { return std::nullopt; }
    return message;
}
static std::optional<Bytes> decrypt(const PPub& p,const PToken& token,const PKey& key,const PCipher& ct) {
    auto delta=partialDecrypt(p,token,ct); if(!delta) return std::nullopt;
    return finishDecrypt(p,token.c,key,ct,*delta);
}

// Shared identity-bound index for RR-ABKS and PR-ABKS. No current revocation
// list is an input to Search; only Encrypt chooses the eligible identities.
struct Identity { E secret,pub; };
static Identity identity(const E& g) { E x=randomElement(*g.ctx,Kind::Scalar); return {x,power(g,x)}; }
struct Tree {
    E g; std::vector<E> internal,identities; std::vector<int> leaf;
    Tree(const E& generator,int users):g(generator) {
        require(users>=2,"Tree needs at least two users");
        for(int j=0;j<users-1;++j) internal.push_back(power(g,randomElement(*g.ctx,Kind::Scalar)));
        leaf.resize(users); std::iota(leaf.begin(),leaf.end(),users-1);
    }
    // Reg inserts public identities into leaf slots. Internal nodes alone
    // contribute to a path product; leaf identity is the separate exponent.
    void bind(const std::vector<E>& ids) {
        require(ids.size()==leaf.size() && identities.empty(),"Invalid or repeated identity registration");
        for(size_t i=0;i<ids.size();++i) {
            require(!ids[i].one(),"Identity cannot be the group unit");
            for(size_t j=0;j<i;++j) require(ids[i]!=ids[j],"Duplicate identity public key");
        }
        identities=ids;
        std::random_device rd; std::mt19937 rng(rd()); std::shuffle(leaf.begin(),leaf.end(),rng);
    }
    E path(int user) const {
        require(identities.size()==leaf.size() && user>=0 && size_t(user)<leaf.size(),"Unknown or unregistered identity slot"); E out(*g.ctx,Kind::G);
        int node=(leaf[user]-1)/2;
        while(true) { out=out*internal.at(node); if(node==0) break; node=(node-1)/2; }
        return out;
    }
};
struct Index { E I1,I2,I3; std::vector<std::vector<E>> rows; };
struct Trapdoor { std::vector<E> terms; E T2,Tid; };
static void keywordSet(const std::vector<std::string>& kw) {
    require(!kw.empty(),"Empty keyword set unsupported");
    require(std::set<std::string>(kw.begin(),kw.end()).size()==kw.size(),"Duplicate keyword");
}
static Index makeIndex(const Tree& tree,const std::vector<E>& ids,const std::set<int>& revoked,const std::vector<std::string>& keywords) {
    keywordSet(keywords); require(ids.size()==tree.leaf.size(),"Identity set size mismatch");
    require(ids.size()==tree.identities.size(),"Tree is not registered");
    for(size_t i=0;i<ids.size();++i) require(ids[i]==tree.identities[i],"Identity/tree registration mismatch");
    for(int i:revoked) require(i>=0 && size_t(i)<ids.size(),"Invalid revoked identity");
    Context& c=*tree.g.ctx; E v=randomElement(c,Kind::Scalar),rho=randomElement(c,Kind::Scalar),sum=scalar(c,0);
    std::vector<E> bl; for(size_t k=0;k<keywords.size();++k) { bl.push_back(randomElement(c,Kind::Scalar)); sum=sum+bl.back(); }
    Index out{power(tree.g,v),power(tree.g,sum),power(tree.g,neg(rho)),{}};
    for(size_t j=0;j<ids.size();++j) if(!revoked.count(j)) {
        E rid=power(pair(tree.path(j),ids[j]),v); E binding=h1(rid); std::vector<E> row;
        for(size_t k=0;k<keywords.size();++k) row.push_back(power(tree.g,bl[k]*binding)*power(h2(c,keywords[k]),rho));
        out.rows.push_back(std::move(row));
    }
    return out;
}
static Trapdoor trapdoor(const Tree& tree,int user,const E& secret,const std::vector<std::string>& query) {
    keywordSet(query); Context& c=*tree.g.ctx; E tau=randomElement(c,Kind::Scalar); std::vector<E> terms;
    for(const auto& word:query) terms.push_back(power(h2(c,word),tau));
    return {terms,power(tree.g,tau),power(tree.path(user),secret)};
}
static bool search(const Index& index,const Trapdoor& trap) {
    Context& c=*index.I1.ctx; E rid=pair(trap.Tid,index.I1),qproduct(c,Kind::G);
    for(const auto& t:trap.terms) qproduct=qproduct*t;
    E right=pair(index.I2,power(trap.T2,h1(rid)));
    E queryTerm=pair(index.I3,qproduct);
    for(const auto& row:index.rows) {
        E product(c,Kind::G); for(const auto& component:row) product=product*component;
        if(pair(product,trap.T2)*queryTerm==right) return true;
    }
    return false;
}

// RR-ABKS: negative W exponent is the explicitly documented consistency
// convention for the reference's C3=...U^{-k}, C4=g^{-k}, product decryption.
struct RSetup {
    E g,h,Z; int n,universe; std::vector<E> A,B,P;
    std::vector<std::vector<E>> U;
    std::vector<std::vector<std::vector<E>>> W;
    RSetup(Context& c,int users,int attrs):g(randomElement(c,Kind::G)),h(c,Kind::G),Z(c,Kind::GT),n(users),universe(attrs) {
        require(n>=2 && universe>0,"Invalid RR setup sizes"); E a=randomElement(c,Kind::Scalar);
        auto ap=powers(a,n+2); E alpha=neg(ap[n+1]); Z=power(pair(g,g),alpha);
        for(int i=1;i<=n;++i) h=h*power(g,ap[n+1-i]);
        for(int i=0;i<n;++i) { A.push_back(power(g,ap[i+1])); B.push_back(power(g,alpha)*power(h,ap[i+1])); P.push_back(power(g,randomElement(c,Kind::Scalar))); }
        U.assign(n,std::vector<E>(universe,E(c,Kind::G)));
        W.assign(n,std::vector<std::vector<E>>(n,std::vector<E>(universe,E(c,Kind::G))));
        for(int j=0;j<n;++j) for(int w=0;w<universe;++w) {
            E u=randomElement(c,Kind::Scalar); U[j][w]=power(g,u);
            for(int i=0;i<n;++i) if(i!=j) W[i][j][w]=power(A[i],neg(u));
        }
    }
};
struct RUser { E r,T,Q1,Q2; Identity id; std::vector<E> V; };
static RUser keygen(const RSetup& s,int i) {
    E r=randomElement(*s.g.ctx,Kind::Scalar); Identity id=identity(s.g);
    std::vector<E> V(s.n,E(*s.g.ctx,Kind::G));
    for(int j=0;j<s.n;++j) if(i!=j) V[j]=power(s.A[j],r);
    return {r,power(s.g,r),power(s.P[i],r),power(s.P[i],id.secret),id,V};
}
static bool valid(const RSetup& s,int i,const RUser& u) {
    if(pair(u.T,s.P[i])!=pair(s.g,u.Q1) || pair(u.id.pub,s.P[i])!=pair(s.g,u.Q2)) return false;
    for(int j=0;j<s.n;++j) if(i!=j && pair(s.g,u.V[j])!=pair(u.T,s.A[j])) return false;
    return true;
}
struct RPub { E g,h,Z,T; std::vector<E> U; };
struct RToken { E A,B,V; std::vector<E> W; Attrs attrs; };
struct RRegistered { RPub pub; std::vector<RToken> tokens; };
static RRegistered aggregate(const RSetup& s,const std::vector<RUser>& users,const std::vector<Attrs>& attrs) {
    Context& c=*s.g.ctx; require(users.size()==size_t(s.n) && attrs.size()==users.size(),"RR aggregation size mismatch");
    E T(c,Kind::G); std::vector<E> U(s.universe,E(c,Kind::G)); std::vector<RToken> tokens;
    for(const auto& user:users) T=T*user.T;
    for(int w=0;w<s.universe;++w) for(int j=0;j<s.n;++j) if(!attrs[j].count(w)) U[w]=U[w]*s.U[j][w];
    for(int i=0;i<s.n;++i) {
        E V(c,Kind::G); std::vector<E> W(s.universe,E(c,Kind::G));
        for(int j=0;j<s.n;++j) if(i!=j) {
            V=V*users[j].V[i];
            for(int w=0;w<s.universe;++w) if(!attrs[j].count(w)) W[w]=W[w]*s.W[i][j][w];
        }
        tokens.push_back({s.A[i],s.B[i],V,W,attrs[i]});
    }
    return {{s.g,s.h,s.Z,T,U},tokens};
}
struct RCipher { Policy policy; E C1,C2,C5; std::vector<E> C3,C4; };
static RCipher encrypt(const RPub& p,const Policy& policy,const E& message) {
    Context& c=*p.g.ctx; policy.validate(p.U.size()); E s=randomElement(c,Kind::Scalar);
    E h1g=randomElement(c,Kind::G),h2g=p.h/h1g; auto lambda=shares(c,policy,s); std::vector<E> C3,C4;
    for(size_t i=0;i<lambda.size();++i) {
        E k=randomElement(c,Kind::Scalar);
        C3.push_back(power(h2g,lambda[i])*power(p.U[policy.rho[i]],neg(k))); C4.push_back(power(p.g,neg(k)));
    }
    return {policy,message*power(p.Z,s),power(p.g,s),power(h1g/p.T,s),C3,C4};
}
static std::optional<E> decrypt(const RPub& p,const RToken& token,const E& r,const RCipher& ct) {
    Context& c=*p.g.ctx; ct.policy.validate(p.U.size());
    if(ct.C3.size()!=ct.policy.rho.size() || ct.C4.size()!=ct.C3.size()) return std::nullopt;
    auto weights=reconstruct(c,ct.policy,token.attrs); if(!weights) return std::nullopt;
    E attr(c,Kind::GT);
    for(const auto& item:*weights) {
        size_t i=item.first; attr=attr*power(pair(ct.C3[i],token.A)*pair(ct.C4[i],token.W[ct.policy.rho[i]]),item.second);
    }
    return (ct.C1/pair(ct.C2,token.B))*pair(ct.C5,token.A)*pair(ct.C2,power(token.A,r)*token.V)*attr;
}

struct Tests {
    int passed=0;
    void check(bool ok,const std::string& name) { require(ok,"TEST FAILED: "+name); ++passed; }
    template<class F> void rejects(F f,const std::string& name) {
        bool rejected=false; try { f(); } catch(const std::runtime_error&) { rejected=true; } check(rejected,name);
    }
};
static std::vector<Attrs> assignment(int n,int universe,bool everyone=false) {
    std::vector<Attrs> attrs(n);
    for(int i=0;i<n;++i) for(int w=0;w<universe;++w)
        if(everyone || i<2 || (w+i)%3==0) attrs[i].insert(w);
    return attrs;
}
static Bytes keyBytes(const PKey& key) {
    Bytes out; append(out,key.base.a.bytes()); append(out,key.base.b.bytes()); append(out,key.base.c.bytes());
    for(const auto& piece:key.pieces) { append(out,piece.a.bytes()); append(out,piece.b.bytes()); append(out,piece.c.bytes()); }
    for(const auto& tag:key.tags) append(out,tag.bytes());
    return out;
}
static bool equals(const std::optional<Bytes>& actual,const Bytes& expected) { return actual && *actual==expected; }
static bool equals(const std::optional<E>& actual,const E& expected) { return actual && *actual==expected; }
static E safeTag(Context& c,const E& td,long start) {
    E t=scalar(c,start); while(t==td) t=t+scalar(c,1); return t;
}
static void testPuncturable(Context& c,Tests& t,bool allAttributes,int eta) {
    PSetup setup(c,4,4,eta); auto attrs=assignment(4,4,allAttributes);
    std::vector<PUser> users; std::vector<Registration> publicUsers;
    for(int i=0;i<4;++i) { users.push_back(keygen(setup,i)); publicUsers.push_back(users.back().registration); }
    auto reg=registration(setup,publicUsers,attrs); const auto& p=reg.pub;
    for(int i=0;i<4;++i) for(int j=0;j<4;++j) if(i!=j) for(int w=0;w<4;++w)
        t.check(pair(setup.g,setup.W[i][j][w])==pair(setup.U[j][w],power(setup.hi[i],setup.c[i])*setup.F[i]),"W generation and initialization order");
    for(int i=0;i<4;++i) for(int w:attrs[i])
        t.check(pair(setup.g,reg.tokens[i].W[w])==pair(p.U[w],power(setup.hi[i],setup.c[i])*setup.F[i]),"Token W index orientation and empty products");
    auto badPublic=publicUsers; badPublic[0].cross[1]=badPublic[0].cross[1]*setup.g;
    t.rejects([&]{registration(setup,badPublic,attrs);},"Invalid cross term rejected");
    Policy policy=Policy::all(4); Bytes message{0,0,65,0,255,19,0};
    E tag=safeTag(c,p.td,5),other=safeTag(c,p.td,100);
    std::vector<E> tags; if(eta>1) tags.push_back(tag);
    auto ct=encrypt(p,policy,message,tags);
    t.check(equals(decrypt(p,reg.tokens[0],users[0].key,ct),message),"Initial-key full AND decryption");
    t.check(equals(decrypt(p,reg.tokens[1],users[1].key,ct),message),"Second authorized user");
    auto delta=partialDecrypt(p,reg.tokens[0],ct);
    t.check(delta && equals(finishDecrypt(p,reg.tokens[0].c,users[0].key,ct,*delta),message),"Split partial and local decryption");
    if(!allAttributes) {
        t.check(!decrypt(p,reg.tokens[2],users[2].key,ct),"Unauthorized attribute set");
        auto forged=reg.tokens[2]; forged.attrs=attrs[0];
        t.check(!decrypt(p,forged,users[2].key,ct),"Bypassing policy guard does not repair missing attribute token");
    }
    PKey updated=users[0].key;
    for(int i=0;i<3;++i) {
        E punctured=safeTag(c,p.td,100+i*10); updated=puncture(p,reg.tokens[0].c,updated,punctured);
        t.check(equals(decrypt(p,reg.tokens[0],updated,ct),message),"Sequential nonmatching punctures retain decryption");
    }
    auto same=puncture(p,reg.tokens[0].c,updated,updated.tags[0]);
    t.check(keyBytes(same)==keyBytes(updated),"Repeated puncture is idempotent");
    for(size_t i=0;i<updated.pieces.size();++i) for(int k=0;k<3;++k) {
        auto bad=updated; E* e=k==0?&bad.pieces[i].a:(k==1?&bad.pieces[i].b:&bad.pieces[i].c); *e=*e*p.g;
        t.check(!decrypt(p,reg.tokens[0],bad,ct),"Every puncture key component participates in recovery");
    }
    for(int k=0;k<3;++k) {
        auto bad=updated; E* e=k==0?&bad.base.a:(k==1?&bad.base.b:&bad.base.c); *e=*e*p.g;
        t.check(!decrypt(p,reg.tokens[0],bad,ct),"Every base-key component participates in recovery");
    }
    if(eta>1) {
        auto blocked=puncture(p,reg.tokens[0].c,updated,tag);
        t.check(!decrypt(p,reg.tokens[0],blocked,ct),"Matching puncture rejects ciphertext");
        t.check(equals(decrypt(p,reg.tokens[0],users[0].key,ct),message),"Retained old key remains usable: stated erasure boundary");
        t.check(equals(decrypt(p,reg.tokens[1],users[1].key,ct),message),"Puncturing one user does not change another key");
        auto newct=encrypt(p,policy,message,{other});
        t.check(equals(decrypt(p,reg.tokens[0],puncture(p,reg.tokens[0].c,users[0].key,tag),newct),message),"Other ciphertext tag remains decryptable");
        t.rejects([&]{encrypt(p,policy,message,{p.td});},"Distinguished tag excluded");
        auto malformed=ct; malformed.tags={p.td};
        t.check(!decrypt(p,reg.tokens[0],users[0].key,malformed),"Zero distinguished-tag denominator rejected");
    }
    for(size_t row=0;row<ct.C3.size();++row) {
        auto corrupt=ct; corrupt.C3[row]=corrupt.C3[row]*p.g;
        t.check(!decrypt(p,reg.tokens[0],users[0].key,corrupt),"Each AND-policy ciphertext row is necessary");
    }
    for(size_t k=0;k<ct.C5.size();++k) {
        auto corrupt=ct; corrupt.C5[k]=corrupt.C5[k]*p.g;
        t.check(!decrypt(p,reg.tokens[0],updated,corrupt),"Each tag-polynomial ciphertext component is necessary");
    }
    auto corrupt=ct; corrupt.C1[0]^=1;
    t.check(!decrypt(p,reg.tokens[0],users[0].key,corrupt),"Tampered C1 rejected");
    corrupt=ct; corrupt.C7=corrupt.C7*p.g;
    t.check(!decrypt(p,reg.tokens[0],users[0].key,corrupt),"Tampered C7 rejected");
    t.check(!finishDecrypt(p,reg.tokens[0].c,users[0].key,ct,*delta*pair(p.g,p.g)),"Tampered partial decryption rejected");
    for(int m=0;m<eta;++m) {
        std::vector<E> set; for(int k=0;k<m;++k) set.push_back(safeTag(c,p.td,200+k*10));
        auto boundary=encrypt(p,policy,message,set);
        t.check(equals(decrypt(p,reg.tokens[0],updated,boundary),message),"All tag counts from zero through eta-1");
    }
    std::vector<E> tooMany; for(int k=0;k<eta;++k) tooMany.push_back(safeTag(c,p.td,300+k*10));
    t.rejects([&]{encrypt(p,policy,message,tooMany);},"Tag capacity overflow rejected");
    t.rejects([&]{encrypt(p,policy,Bytes(64,255),{});},"Out-of-domain message rejected without reduction");
    for(const Policy& general:std::vector<Policy>{Policy{{{1},{1}},{0,1}},Policy{{{1,1},{0,-1},{1,0}},{0,1,2}},
        Policy{{{1,1},{1,2},{1,3}},{0,1,2}}, Policy{{{2,1},{0,3}},{0,1}}}) {
        auto complex=encrypt(p,general,message,tags);
        for(int i=0;i<4;++i) {
            bool allowed=bool(reconstruct(c,general,attrs[i]));
            auto output=decrypt(p,reg.tokens[i],users[i].key,complex);
            t.check(allowed?equals(output,message):!output,"OR, mixed, threshold and fractional-coefficient LSSS policies");
        }
    }
    // Relational tampering also ensures no hidden encryption-session Z^s input.
    std::cout << "PASS PR-ABE/PR-ABKS core: eta="<<eta<<", all_attributes="<<allAttributes<<"\n";
}
static void testSearch(Context& c,Tests& t) {
    E g=randomElement(c,Kind::G); Tree tree(g,5); std::vector<Identity> ids; std::vector<E> publicIds;
    for(int i=0;i<5;++i) { ids.push_back(identity(g)); publicIds.push_back(ids.back().pub); }
    tree.bind(publicIds);
    std::vector<std::string> kw{"alpha","beta","gamma"};
    auto index=makeIndex(tree,publicIds,{4},kw); t.check(index.rows.size()==4,"Index contains all nonrevoked identities");
    for(int i=0;i<5;++i) t.check(search(index,trapdoor(tree,i,ids[i].secret,kw))==(i!=4),"Each identity matches only its generated index entry");
    t.check(search(index,trapdoor(tree,0,ids[0].secret,{"gamma","alpha","beta"})),"Keyword order does not matter");
    t.check(!search(index,trapdoor(tree,0,ids[0].secret,{"alpha","beta"})),"Proper subset rejected");
    t.check(!search(index,trapdoor(tree,0,ids[0].secret,{"alpha","beta","wrong"})),"Wrong keyword rejected");
    t.check(!search(index,trapdoor(tree,0,ids[0].secret,{"alpha","beta","gamma","extra"})),"Superset rejected");
    t.check(!search(index,trapdoor(tree,0,randomElement(c,Kind::Scalar),kw)),"Wrong identity secret rejected");
    auto newer=makeIndex(tree,publicIds,{0,4},kw); auto oldtrap=trapdoor(tree,0,ids[0].secret,kw);
    t.check(search(index,oldtrap) && !search(newer,oldtrap),"Revocation affects new indexes, not historical ones");
    t.check(!search(makeIndex(tree,publicIds,{0,1,2,3,4},kw),oldtrap),"All users revoked");
    t.rejects([&]{makeIndex(tree,publicIds,{}, {"same","same"});},"Duplicate keywords rejected");
    t.rejects([&]{trapdoor(tree,0,ids[0].secret,{});},"Empty query rejected");
    std::cout<<"PASS identity-bound indexes and snapshot revocation\n";
}
static void testRR(Context& c,Tests& t,bool everyone) {
    RSetup setup(c,4,4); auto attrs=assignment(4,4,everyone); std::vector<RUser> users;
    for(int i=0;i<4;++i) { users.push_back(keygen(setup,i)); t.check(valid(setup,i,users.back()),"RR key validation"); }
    auto bad=users[0]; bad.Q1=bad.Q1*setup.g; t.check(!valid(setup,0,bad),"RR rejects invalid public key");
    auto reg=aggregate(setup,users,attrs); E message=randomElement(c,Kind::GT); auto policy=Policy::all(4);
    auto ct=encrypt(reg.pub,policy,message);
    for(int i=0;i<4;++i) {
        auto decoded=decrypt(reg.pub,reg.tokens[i],users[i].r,ct);
        t.check(bool(reconstruct(c,policy,attrs[i]))?equals(decoded,message):!decoded,"RR AND policy and decryption");
    }
    for(size_t row=0;row<ct.C3.size();++row) {
        auto corrupt=ct; corrupt.C3[row]=corrupt.C3[row]*setup.g;
        t.check(!equals(decrypt(reg.pub,reg.tokens[0],users[0].r,corrupt),message),"RR every policy row affects recovery");
    }
    for(int i=0;i<4;++i) for(int w:attrs[i])
        t.check((pair(reg.pub.U[w],reg.tokens[i].A)*pair(setup.g,reg.tokens[i].W[w])).one(),"RR W sign and empty product cancellation");
    Policy mixed{{{1,1},{0,-1},{1,0}},{0,1,2}}; auto complex=encrypt(reg.pub,mixed,message);
    for(int i=0;i<4;++i) {
        auto decoded=decrypt(reg.pub,reg.tokens[i],users[i].r,complex);
        t.check(bool(reconstruct(c,mixed,attrs[i]))?equals(decoded,message):!decoded,"RR mixed LSSS policy");
    }
    std::cout<<"PASS RR-ABKS full decryption: all_attributes="<<everyone<<"\n";
}
static void selfTest(Context& c) {
    Tests t;
    const Bytes expected{0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
    t.check(digest(textBytes("abc"))==expected,"SHA256 known vector");
    t.check(digest(Bytes{1,0,2})!=digest(Bytes{1}),"Binary hashing does not truncate at zero bytes");
    Policy and2=Policy::all(2); t.check(!reconstruct(c,and2,{0}) && bool(reconstruct(c,and2,{0,1})),"LSSS AND semantics");
    Policy or2{{{1},{1}},{0,1}}; t.check(bool(reconstruct(c,or2,{1})) && !reconstruct(c,or2,{}),"LSSS OR semantics");
    Policy threshold{{{1,1},{1,2},{1,3}},{0,1,2}};
    t.check(!reconstruct(c,threshold,{1}) && bool(reconstruct(c,threshold,{0,2})),"Two-of-three threshold semantics");
    testPuncturable(c,t,false,3); testPuncturable(c,t,true,3); testPuncturable(c,t,false,1);
    testSearch(c,t); testRR(c,t,false); testRR(c,t,true);
    std::cout<<"ALL "<<t.passed<<" CHECKS PASSED\n";
}

struct Config { int users=10,attrs=10,policy=4,eta=3,tags=1,punctures=1,keywords=10,runs=10,warmup=1; };
using Timing=std::map<std::string,double>;
template<class F> static auto timed(Timing& t,const std::string& name,F f) {
    auto start=std::chrono::steady_clock::now(); auto result=f();
    t[name]+=std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-start).count(); return result;
}
static Timing benchmarkP(Context& c,const Config& cfg,bool searchable) {
    Timing times;
    auto setup=timed(times,"Setup",[&]{return PSetup(c,cfg.users,cfg.attrs,cfg.eta);});
    std::optional<Tree> tree;
    if(searchable) tree=timed(times,"Setup",[&]{return Tree(setup.g,cfg.users);});
    std::vector<PUser> users; std::vector<Identity> ids;
    timed(times,"KeyGen",[&]{
        for(int i=0;i<cfg.users;++i) { users.push_back(keygen(setup,i)); if(searchable) ids.push_back(identity(setup.g)); }
        return true;
    });
    auto attrs=assignment(cfg.users,cfg.attrs); std::vector<Registration> publicUsers; std::vector<E> publicIds;
    for(const auto& u:users) publicUsers.push_back(u.registration);
    for(const auto& id:ids) publicIds.push_back(id.pub);
    auto reg=timed(times,"Reg",[&]{return registration(setup,publicUsers,attrs);});
    if(searchable) timed(times,"Reg",[&]{tree->bind(publicIds); return true;});
    auto policy=Policy::all(cfg.policy); Bytes message=textBytes("PR-ABKS"); std::vector<E> tags;
    for(int k=0;k<cfg.tags;++k) tags.push_back(safeTag(c,reg.pub.td,10+k*10));
    std::vector<std::string> kw; for(int k=0;k<cfg.keywords;++k) kw.push_back("kw"+std::to_string(k));
    auto ct=timed(times,"Enc",[&]{return encrypt(reg.pub,policy,message,tags);});
    std::optional<Index> index; std::optional<Trapdoor> trap;
    if(searchable) {
        index=timed(times,"Enc",[&]{return makeIndex(*tree,publicIds,{cfg.users-1},kw);});
        trap=timed(times,"TrapGen",[&]{return trapdoor(*tree,0,ids[0].secret,kw);});
        bool found=timed(times,"Search",[&]{return search(*index,*trap);}); require(found,"Benchmark search failed");
    }
    PKey current=users[0].key;
    timed(times,"KeyUpt",[&]{for(int k=0;k<cfg.punctures;++k) current=puncture(reg.pub,reg.tokens[0].c,current,safeTag(c,reg.pub.td,10000+k*10)); return true;});
    auto recovered=timed(times,"Dec",[&]{return decrypt(reg.pub,reg.tokens[0],current,ct);});
    require(equals(recovered,message),"Benchmark puncturable decryption failed"); return times;
}
static Timing benchmarkR(Context& c,const Config& cfg) {
    Timing times; auto setup=timed(times,"Setup",[&]{return RSetup(c,cfg.users,cfg.attrs);});
    auto tree=timed(times,"Setup",[&]{return Tree(setup.g,cfg.users);}); std::vector<RUser> users;
    timed(times,"KeyGen",[&]{for(int i=0;i<cfg.users;++i) users.push_back(keygen(setup,i)); return true;});
    timed(times,"IsValid",[&]{for(int i=0;i<cfg.users;++i) require(valid(setup,i,users[i]),"RR validation failed"); return true;});
    auto attrs=assignment(cfg.users,cfg.attrs);
    auto reg=timed(times,"Reg",[&]{return aggregate(setup,users,attrs);});
    std::vector<E> ids; for(const auto& user:users) ids.push_back(user.id.pub);
    timed(times,"Reg",[&]{tree.bind(ids); return true;});
    std::vector<std::string> kw; for(int k=0;k<cfg.keywords;++k) kw.push_back("kw"+std::to_string(k));
    E message=randomElement(c,Kind::GT); auto policy=Policy::all(cfg.policy);
    auto ct=timed(times,"Enc",[&]{return encrypt(reg.pub,policy,message);});
    auto index=timed(times,"Enc",[&]{return makeIndex(tree,ids,{cfg.users-1},kw);});
    auto trap=timed(times,"TrapGen",[&]{return trapdoor(tree,0,users[0].id.secret,kw);});
    require(timed(times,"Search",[&]{return search(index,trap);}),"RR search failed");
    auto recovered=timed(times,"Dec",[&]{return decrypt(reg.pub,reg.tokens[0],users[0].r,ct);});
    require(equals(recovered,message),"RR benchmark decryption failed"); return times;
}
static void benchmark(Context& c,const Config& cfg,const std::string& output) {
    require(cfg.users>=2 && cfg.attrs>0 && cfg.policy>0 && cfg.policy<=cfg.attrs && cfg.eta>0 && cfg.tags>=0 && cfg.tags<cfg.eta && cfg.punctures>=0 && cfg.keywords>0 && cfg.runs>0 && cfg.warmup>=0,"Invalid benchmark configuration");
    require(!output.empty(),"Benchmark requires --output NEW.csv");
    std::ifstream existing(output); require(!existing.good(),"Refusing to overwrite existing output: "+output);
    std::map<std::string,std::map<std::string,std::vector<double>>> samples;
    for(const std::string scheme:{"PR-ABE","RR-ABKS","PR-ABKS"}) {
        for(int run=-cfg.warmup;run<cfg.runs;++run) {
            Timing t=scheme=="RR-ABKS"?benchmarkR(c,cfg):benchmarkP(c,cfg,scheme=="PR-ABKS");
            if(run>=0) for(const auto& item:t) samples[scheme][item.first].push_back(item.second);
        }
        std::cout<<scheme<<": "<<cfg.runs<<" validated runs completed\n";
    }
    std::ofstream csv(output); require(bool(csv),"Cannot create output: "+output);
    csv<<"scheme,algorithm,N,U,policy_rows,eta,ciphertext_tags,punctures,keywords,eligible_users,runs,warmup,total_ms,mean_ms,sample_sd_ms,min_ms,max_ms\n"<<std::setprecision(10);
    for(const auto& scheme:samples) for(const auto& row:scheme.second) {
        const auto& v=row.second; double total=std::accumulate(v.begin(),v.end(),0.0),mean=total/v.size(),variance=0;
        for(double value:v) variance+=(value-mean)*(value-mean);
        csv<<scheme.first<<','<<row.first<<','<<cfg.users<<','<<cfg.attrs<<','<<cfg.policy<<',';
        if(scheme.first=="RR-ABKS") csv<<"--,--,--,"; else csv<<cfg.eta<<','<<cfg.tags<<','<<cfg.punctures<<',';
        if(scheme.first=="PR-ABE") csv<<"--,--,"; else csv<<cfg.keywords<<','<<cfg.users-1<<',';
        csv<<cfg.runs<<','<<cfg.warmup<<','<<total<<','<<mean<<',';
        if(v.size()>1) csv<<std::sqrt(variance/(v.size()-1)); else csv<<"--";
        csv<<','<<*std::min_element(v.begin(),v.end())<<','<<*std::max_element(v.begin(),v.end())<<'\n';
    }
    require(bool(csv),"Failed writing benchmark output");
}
int main(int argc,char** argv) {
    try {
        Config cfg; std::string parameters=DEFAULT_PARAM_FILE,output; bool bench=false;
        for(int i=1;i<argc;++i) {
            std::string arg=argv[i];
            if(arg=="--self-test") { bench=false; continue; }
            if(arg=="--benchmark") { bench=true; continue; }
            if(arg=="--help") {
                std::cout<<"prabks --self-test [--params FILE]\nprabks --benchmark --output NEW.csv [--users 10 --attrs 10 --policy 4 --eta 3 --tags 1 --punctures 1 --keywords 10 --runs 10 --warmup 1 --params FILE]\n"; return 0;
            }
            require(i+1<argc,"Missing value for "+arg); std::string value=argv[++i];
            if(arg=="--params") parameters=value;
            else if(arg=="--output") output=value;
            else {
                size_t consumed=0; int n=std::stoi(value,&consumed); require(consumed==value.size(),"Invalid integer");
                if(arg=="--users") cfg.users=n; else if(arg=="--attrs") cfg.attrs=n;
                else if(arg=="--policy") cfg.policy=n; else if(arg=="--eta") cfg.eta=n;
                else if(arg=="--tags") cfg.tags=n; else if(arg=="--punctures") cfg.punctures=n;
                else if(arg=="--keywords") cfg.keywords=n; else if(arg=="--runs") cfg.runs=n;
                else if(arg=="--warmup") cfg.warmup=n; else throw std::runtime_error("Unknown argument: "+arg);
            }
        }
        Context context(parameters);
        if(bench) benchmark(context,cfg,output); else selfTest(context);
        return 0;
    } catch(const std::exception& error) { std::cerr<<"ERROR: "<<error.what()<<'\n'; return 1; }
}
