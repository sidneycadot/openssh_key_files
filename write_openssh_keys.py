#! /usr/bin/env python3

import base64
import io
from typing import NamedTuple, Optional, BinaryIO


def write_fixed_size_integer(fo: BinaryIO, n: int, size: int) -> None:
    blob = n.to_bytes(length=size, byteorder='big', signed=False)
    fo.write(blob)


def write_variable_size_blob(fo: BinaryIO, blob: bytes) -> None:
    blob_size = len(blob)
    write_fixed_size_integer(fo, blob_size, 4)
    fo.write(blob)


def write_variable_size_string(fo: BinaryIO, s: str) -> None:
    blob = s.encode('utf-8')
    write_variable_size_blob(fo, blob)


def write_variable_size_integer(fo: BinaryIO, n: int) -> None:
    # We cannot just use int.to_bytes, because for large numbers we get an OverflowError.
    octets = []
    while n != 0:
        octets.append(n % 0x100)
        n //= 0x100
    if len(octets) != 0 and octets[-1] > 0x7f:
        octets.append(0)
    blob = bytes(reversed(octets))
    write_variable_size_blob(fo, blob)


class openssh_rsa_key(NamedTuple):
    n: int
    e: int
    d: int
    iqmp: int
    p: int
    q: int
    comment: str

    def encode_public_key(self) -> bytes:
        with io.BytesIO() as fo:
            write_variable_size_string(fo, "ssh-rsa")
            write_variable_size_integer(fo, self.e)
            write_variable_size_integer(fo, self.n)
            return fo.getvalue()

    def encode_private_key(self, check: int, cipher_blocksize: int) -> bytes:

        with io.BytesIO() as fo:
            write_fixed_size_integer(fo, check, 4)
            write_fixed_size_integer(fo, check, 4) # Same 'check' value is repeated twice.
            write_variable_size_string(fo, "ssh-rsa")
            write_variable_size_integer(fo, self.n)
            write_variable_size_integer(fo, self.e)
            write_variable_size_integer(fo, self.d)
            write_variable_size_integer(fo, self.iqmp)
            write_variable_size_integer(fo, self.p)
            write_variable_size_integer(fo, self.q)
            write_variable_size_string(fo, self.comment)


            padding_size = -len(fo.getbuffer()) % cipher_blocksize
            padding = bytes((i + 1) % 0x100 for i in range(padding_size))
            fo.write(padding)

            return fo.getvalue()

    def encode_private_key_file_data(self, check: int) -> bytes:

        auth_magic = b"openssh-key-v1\x00"
        ciphername = "none"
        kdfname = "none"
        kdf = ""
        number_of_keys = 1

        cipher_blocksize = 4

        with io.BytesIO() as fo:

            fo.write(auth_magic)
            write_variable_size_string(fo, ciphername)
            write_variable_size_string(fo, kdfname)
            write_variable_size_string(fo, kdf)
            write_fixed_size_integer(fo, number_of_keys, 4)
            
            encoded_public_key = self.encode_public_key()
            write_variable_size_blob(fo, encoded_public_key)

            encoded_private_key = self.encode_private_key(check, cipher_blocksize)
            write_variable_size_blob(fo, encoded_private_key)

            return fo.getvalue()

    def get_public_key_file_contents(self) -> str:
        encoded_public_key = self.encode_public_key()
        encoded_public_key_base64 = base64.b64encode(encoded_public_key).decode('ascii')
        return "ssh-rsa {} {}".format(encoded_public_key_base64, self.comment)

    def get_private_key_file_contents(self, check: Optional[int]=None) -> str:

        if check is None:
            check = 0

        encoded_private_key = self.encode_private_key_file_data(check)

        encoded_private_key_base64 = base64.b64encode(encoded_private_key).decode('ascii')

        max_line_length = 70

        with io.StringIO() as fo:
            print("-----BEGIN OPENSSH PRIVATE KEY-----", file=fo)
            offset = 0
            while offset < len(encoded_private_key_base64):
                print(encoded_private_key_base64[offset:offset + max_line_length], file=fo)
                offset += max_line_length
            print("-----END OPENSSH PRIVATE KEY-----", file=fo, end='')

            return fo.getvalue()


def main():

    # Data for an example key that was generated using ssh-keygen.
    key = openssh_rsa_key(
            n = 4132016562717647960298574368311551209470192788960737107937024114871020897556237509284939846122129270407687253869953377513758578694270994512724894178629035253579230691905977394287337795553178586086692777931840844352311398935218295334607934424645951724132211389175078614305776900793645170827772112762785709851862093842691005881853525811222826922074943452254990506698115264186860075908030370836664052073301814010843324186939041350514971919660268895137756918698490253938865753993595943299637536910301642788473137356723826739604421666732312824082050454739006575828295222687730829869694198307579858316045024002445372517867450067093354898960180178953025646331062412954409904978988941212865928494625669154416918293072899498392576654804299245920601365397426363345902095510842892458307173260173450988528447645957610276720999321348429384053542961346170348475415591556260144251019873198969713171523626594702144627516258849337051303364341,
            e = 65537,
            d = 2466272363456158128431257664605382435278476758560464370526154268602617215461607071588552908444990321048224702223644144043909460652513824135286322010245082503231133054233274604152429811383702133938891944922102298068714847981276745328651884750429157477346837861213689216103866137118650810187679657825989725075534271096396601569807351101783775893171880968336336171178268379529081367613629308879225288385970475588784325071646466583885349597652482389659331940563786000324337241349636948239586079123403558163436067565732448400026030665778853872208469824640994916758754733046149060366313667988587080741220652712025174775814629395631267077622751489862749658880268604927920324853102126431648295278304627013198338953864120012439295885373614235463583361724488800028755056082460438695189348497815562264398150739539923613285587240723346941143029749560527623271207414835707816218866278943804309969503990971893055429895321351941652544585473,
            iqmp = 1606673233196350142404922723433282675026643791644789726598606546686002801445895236750180857904867915574695425032646786503607028684812745642723235608439280098615813056658237705092944546663342794456182539649169157410873147491124435293587019027406955359273295833421488225555657794023287207250497659136455579075620900773926384618319169822558618215480873390164136751875499409421879294170621977888762178661826734434472717029111099135966000270831961315722485436082662019,
            p = 2279063046225628786043189451917885280273341560883553340905610610870977627707603830157831765261794176152241814642514703118760487896366968650802224876181991158879956670265645298047336601780744703995191348827060234803019383947706921840816990479962059395690330889900397997271383227048053725511275738186362619539388844071222640932555991265951100077645056154579683288826172514686704162309392225735502704207375833207801477832510770953047318282365806979558748866108031541,
            q = 1813033022303050198471833905287671648161855262848521165313695578013507867972450649499108410016653989997673324450533990009450509107677599063672700648717639632785380763921957613823946228697397689461525079782576632961724148076662790099253806029301195449426201264573775615670639405076928080469947697459510566841303054013086402868814165077366375594501340496478882054214815590211985150436344607645094438848357768680297916170292590926574841101474607771622766008576100801,
            comment = 'sidney@hercules'
        )

    # Write public key.
    public_key_file_contents = key.get_public_key_file_contents()
    with open("regenerate_key.pub", "w") as fo:
        print(public_key_file_contents, file=fo)

    # Write private key.
    check = 0xab78db12  # This is a 32-bit random value that is stored inside the private key file prior to encryption.
    private_key_file_contents = key.get_private_key_file_contents(check)
    with open("regenerate_key", "w") as fo:
        print(private_key_file_contents, file=fo)


if __name__ == "__main__":
    main()
