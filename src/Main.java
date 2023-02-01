import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Main {
	public static void main(String[] args) {
		Scanner sc = new Scanner(System.in);
		BigInteger n = sc.nextBigInteger();
		BigInteger u1_max = sc.nextBigInteger();
		BigInteger[] publicKeys = new BigInteger[n.intValue()];
		for (int i = 0; i < n.intValue(); i++) {
			publicKeys[i] = sc.nextBigInteger();
		}
		EquationSolver solver = new EquationSolver(u1_max, publicKeys);
		Pair solution = solver.solve();
		BigInteger realN = solution.u0();
		BigInteger realQ = solution.u1();
		BigInteger[] privateKey = solver.getUs(publicKeys, realN, realQ);
		BigInteger inverseQ = realQ.modInverse(realN);
		int k = sc.nextInt();
		for (int i = 0; i < k; i++) {
			BigInteger encryptedMessage2 = sc.nextBigInteger();
			BigInteger bigM2 = (encryptedMessage2.multiply(inverseQ)).mod(realN);
			System.out.print(EquationSolver.decrypt(bigM2, privateKey));
		}

	}

	record Pair(BigInteger u0, BigInteger u1) {
	}

	static class EquationSolver {
		private final BigInteger u1Max;
		private final BigInteger[] publicKeys;
		private final ArrayList<Pair> pairsOfPossibleU0AndU1 = new ArrayList<>();

		public EquationSolver(BigInteger u1Max, BigInteger[] publicKeys) {
			this.u1Max = u1Max;
			this.publicKeys = publicKeys;
		}

		public static String decrypt(BigInteger bigM, BigInteger[] realUs) {
			StringBuilder sb = new StringBuilder();
			BigInteger sum = BigInteger.ZERO;
			for (int i = realUs.length - 1; i >= 0; i--) {
				BigInteger u = realUs[i];
				if (sum.add(u)
						.compareTo(bigM) <= 0) {
					sum = sum.add(u);
					sb.append("1");
				} else {
					sb.append("0");
				}
			}
			String bitArray = sb.reverse()
					.toString();
			StringBuilder message = new StringBuilder();
			for (int i = 0; i < bitArray.length(); i += 8) {
				String byteString = bitArray.substring(i, i + 8);
				message.append((char) Integer.parseInt(byteString, 2));
			}
			return message.toString();
		}

		public Pair solve() {
			generatePairsOfPossibleU0AndU1();
			BigInteger theSmallestPossibleN = getTheSmallestPossibleN();
			for (Pair pair : pairsOfPossibleU0AndU1) {
				System.out.println("Trying pair: " + pair);
				List<BigInteger> possibleNs = getPossibleNs(publicKeys[0], pair.u0(), publicKeys[1], pair.u1(),
						theSmallestPossibleN);
				for (BigInteger n : possibleNs) {
					BigInteger realQ = getRealQ(n, pair.u0(), publicKeys[0]);
					if (realQ != null) {
						return new Pair(n, realQ);
					}
				}
			}
			throw new RuntimeException("No solution found");
		}

		private void generatePairsOfPossibleU0AndU1() {
			for (BigInteger i = BigInteger.ONE; i.compareTo(u1Max) <= 0; i = i.add(BigInteger.ONE)) {
				for (BigInteger j = i; j.compareTo(u1Max) <= 0; j = j.add(BigInteger.ONE)) {
					if (!i.equals(j)) {
						pairsOfPossibleU0AndU1.add(new Pair(i, j));
					}
				}
			}
		}

		private BigInteger getTheSmallestPossibleN() {
			BigInteger max = publicKeys[0];
			for (BigInteger publicKey : publicKeys) {
				max = max.max(publicKey);
			}
			return max.add(BigInteger.ONE);
		}

		public static List<BigInteger> getPossibleNs(BigInteger a0, BigInteger u0, BigInteger a1, BigInteger u1,
				BigInteger theSmallestPossibleN) {
			BigInteger N = a0.multiply(u1)
					.subtract(u0.multiply(a1))
					.abs();
			if (N.compareTo(theSmallestPossibleN) < 0) {
				return List.of();
			}
			return getDividers(N, theSmallestPossibleN);
		}

		private BigInteger getRealQ(BigInteger n, BigInteger u0, BigInteger a0) {
			for (BigInteger i = BigInteger.ONE; i.compareTo(u0) <= 0; i = i.add(BigInteger.ONE)) {
				BigInteger q = a0.add(i.multiply(n))
						.divide(u0);
				if (q.compareTo(n) < 0 && isCoprime(q, n) && isSolution(q, n)) {
					return q;
				}
			}
			return null;
		}

		public static List<BigInteger> getDividers(BigInteger n, BigInteger theSmallestPossibleN) {
			List<BigInteger> dividers = new ArrayList<>();
			BigInteger sqrtN = n.sqrt();
			BigInteger first = n.divide(theSmallestPossibleN);
			BigInteger max = sqrtN.compareTo(first) < 0 ? sqrtN : first;
			for (BigInteger i = BigInteger.ONE; i.compareTo(max) <= 0; i = i.add(BigInteger.ONE)) {
				if (n.mod(i)
						.equals(BigInteger.ZERO)) {
					BigInteger invertedI = n.divide(i);
					if (!i.equals(invertedI) && invertedI.compareTo(theSmallestPossibleN) >= 0) {
						dividers.add(invertedI);
					}
					if (i.compareTo(theSmallestPossibleN) >= 0) {
						dividers.add(i);
					}
				}
			}
			return dividers;
		}

		public static boolean isCoprime(BigInteger x, BigInteger y) {
			return x.gcd(y)
					.equals(BigInteger.ONE);
		}

		private boolean isSolution(BigInteger q, BigInteger n) {
			BigInteger sum = BigInteger.ZERO;
			BigInteger qInverse = q.modInverse(n);
			BigInteger lastU = new BigInteger("-1");
			for (BigInteger a : publicKeys) {
				BigInteger u = (a.multiply(qInverse)).mod(n);
				sum = sum.add(u);
				if (u.compareTo(lastU) < 0 || sum.equals(n) || sum.compareTo(n) > 0) {
					return false;
				}
				lastU = u;
			}
			return !sum.equals(n) && sum.compareTo(n) <= 0;
		}

		public BigInteger[] getUs(BigInteger[] publicKeys, BigInteger n, BigInteger q) {
			BigInteger[] us = new BigInteger[publicKeys.length];
			BigInteger qInverse = q.modInverse(n);
			for (int i = 0; i < publicKeys.length; i++) {
				BigInteger a = publicKeys[i];
				BigInteger u = (a.multiply(qInverse)).mod(n);
				us[i] = u;
			}
			return us;
		}
	}
}
