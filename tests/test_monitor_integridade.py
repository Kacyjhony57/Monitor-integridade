import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import monitor_integridade as m  # noqa: E402


def escrever(pasta, rel, conteudo="x"):
    caminho = os.path.join(pasta, *rel.split("/"))
    os.makedirs(os.path.dirname(caminho), exist_ok=True)
    with open(caminho, "w", encoding="utf-8") as f:
        f.write(conteudo)
    return caminho


def rodar(*argv):
    """Executa o CLI e devolve (codigo, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        codigo = m.main(list(argv))
    return codigo, out.getvalue(), err.getvalue()


class TestFIM(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.raiz = self._tmp.name
        self.pasta = os.path.join(self.raiz, "alvo")
        os.makedirs(self.pasta)
        self.base = os.path.join(self.raiz, "base.json")
        escrever(self.pasta, "a.txt", "alpha")
        escrever(self.pasta, "sub/b.txt", "beta")

    def init(self, *extra):
        return rodar("init", self.pasta, "--baseline", self.base, *extra)

    def check(self, *extra):
        return rodar("check", "--baseline", self.base, *extra)

    def test_sha256_conhecido(self):
        caminho = escrever(self.pasta, "abc.txt", "abc")
        self.assertEqual(
            m.sha256_arquivo(caminho),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_sem_mudancas(self):
        self.assertEqual(self.init()[0], 0)
        codigo, saida, _ = self.check()
        self.assertEqual(codigo, 0)
        self.assertIn("Nenhuma alteração", saida)

    def test_detecta_modificado_novo_removido(self):
        self.init()
        escrever(self.pasta, "a.txt", "alterado")
        escrever(self.pasta, "novo.txt", "n")
        os.remove(os.path.join(self.pasta, "sub", "b.txt"))
        codigo, saida, _ = self.check()
        self.assertEqual(codigo, 1)
        self.assertIn("[MODIFICADO] a.txt", saida)
        self.assertIn("[NOVO]       novo.txt", saida)
        self.assertIn("[REMOVIDO]   sub/b.txt", saida)

    @unittest.skipIf(os.name == "nt", "chmod não se aplica no Windows")
    def test_detecta_permissao(self):
        self.init()
        os.chmod(os.path.join(self.pasta, "a.txt"), 0o777)
        codigo, saida, _ = self.check()
        self.assertEqual(codigo, 1)
        self.assertIn("[PERMISSÃO]  a.txt", saida)

    def test_baseline_adulterado(self):
        self.init()
        with open(self.base, encoding="utf-8") as f:
            dados = json.load(f)
        dados["arquivos"]["a.txt"]["sha256"] = "0" * 64  # atacante "esconde" a mudança
        with open(self.base, "w", encoding="utf-8") as f:
            json.dump(dados, f)
        codigo, _, erro = self.check()
        self.assertEqual(codigo, 3)
        self.assertIn("checksum", erro)

    def test_baseline_json_invalido(self):
        with open(self.base, "w", encoding="utf-8") as f:
            f.write("{isso nao e json")
        self.assertEqual(self.check()[0], 3)

    def test_baseline_inexistente(self):
        self.assertEqual(self.check()[0], 2)

    def test_init_nao_sobrescreve_sem_forcar(self):
        self.init()
        self.assertEqual(self.init()[0], 2)
        self.assertEqual(self.init("--forcar")[0], 0)

    def test_init_pasta_inexistente(self):
        codigo, _, _ = rodar("init", os.path.join(self.raiz, "nao-existe"), "--baseline", self.base)
        self.assertEqual(codigo, 2)

    def test_excluir(self):
        escrever(self.pasta, "debug.log", "1")
        escrever(self.pasta, ".git/config", "g")
        self.init("--excluir", "*.log", "--excluir", ".git")
        escrever(self.pasta, "debug.log", "2")       # excluído: não deve alertar
        escrever(self.pasta, ".git/config", "g2")    # excluído: não deve alertar
        self.assertEqual(self.check()[0], 0)

    def test_baseline_dentro_da_pasta_e_ignorado(self):
        self.base = os.path.join(self.pasta, "baseline.json")
        self.init()
        self.assertEqual(self.check()[0], 0)

    def test_saida_json(self):
        self.init()
        escrever(self.pasta, "novo.txt", "n")
        codigo, saida, _ = self.check("--json")
        dados = json.loads(saida)
        self.assertEqual(codigo, 1)
        self.assertEqual(dados["total_mudancas"], 1)
        self.assertEqual(dados["mudancas"]["novos"], ["novo.txt"])

    @unittest.skipIf(os.name == "nt", "symlink exige privilégio no Windows")
    def test_symlink_monitorado_sem_seguir(self):
        alvo_fora = escrever(self.raiz, "fora/segredo.txt", "s")
        os.symlink(alvo_fora, os.path.join(self.pasta, "atalho"))
        self.init()
        with open(self.base, encoding="utf-8") as f:
            self.assertIn("atalho", json.load(f)["arquivos"])
        os.remove(os.path.join(self.pasta, "atalho"))
        os.symlink(os.path.join(self.raiz, "outro"), os.path.join(self.pasta, "atalho"))
        codigo, saida, _ = self.check()
        self.assertEqual(codigo, 1)
        self.assertIn("[MODIFICADO] atalho", saida)

    @unittest.skipIf(os.name == "nt" or os.geteuid() == 0, "root lê qualquer arquivo")
    def test_arquivo_ilegivel_vira_aviso(self):
        caminho = escrever(self.pasta, "trancado.txt", "t")
        os.chmod(caminho, 0)
        self.addCleanup(os.chmod, caminho, 0o600)
        codigo, saida, _ = self.init()
        self.assertEqual(codigo, 0)
        self.assertIn("[AVISO]", saida)


if __name__ == "__main__":
    unittest.main()
